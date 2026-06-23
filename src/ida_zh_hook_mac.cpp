// ============================================================================
// IDA Professional 9.3  macOS / arm64  界面汉化注入库
// ----------------------------------------------------------------------------
// 作用：用 DYLD_INSERT_LIBRARIES 把本 .dylib 注入 IDA 进程，拦截 Qt6 的若干
//       “设置界面文字”的函数，把英文原文按词典换成中文，再交还给 Qt。
//
// 为什么这样做（macOS 与 Linux 的关键差异，逐条说明）：
//   1) IDA 自带的 Qt 用了【自定义命名空间 QT】（大写两字母），所以符号名是
//      __ZN2QT16QCoreApplication9translate...（nm 里看到两个前导下划线）。
//   2) macOS 默认 two-level namespace —— 光“导出一个同名符号”并不会替换掉
//      程序对 Qt 函数的调用（这点和 Linux 的 LD_PRELOAD 完全不同）。必须用
//      苹果的 DYLD_INTERPOSE 机制：把 {我的函数, 原始函数} 成对写进
//      __DATA,__interpose 段，dyld 加载时会把所有“调用原始函数”的地方改成
//      调用我的函数。
//   3) arm64 调用约定（AAPCS）：函数若【按值返回】大于 16 字节的结构体（Qt6 的
//      QString 正好 24 字节），返回槽地址由调用方放在 x8 寄存器，参数仍从 x0
//      起。所以我把替换函数声明成“按值返回 QString”，编译器会自动生成 x8 间接
//      返回 —— 不能像 Linux x86-64 那样把返回指针当第一个参数（那是 x86 的
//      做法，在 arm64 上会整体错位，这正是上一版失效的根因之一）。
//
// 安全取舍（重要）：本库【只】拦截“往界面控件上设置文字”的函数（translate /
//   各种 setText/setTitle/...），【不】拦截 QString::fromUtf8。因为 fromUtf8 会
//   被用来构造一切字符串（包括被分析二进制里的字符串、反汇编文本、路径等），
//   一旦在那里翻译，会把逆向对象里真实出现的英文也误改成中文，污染分析结果。
//   只挂控件设置器，作用范围天然局限在“界面外壳”，不碰被分析内容，最安全。
//
// 词典格式（ida_lang.txt）：每行  L"原文",L"译文",
//   解析时识别 C 转义（\" \\ \n \t \r），所以原文/译文里可以含转义引号。
//   查找路径：① 环境变量 IDA_LANG 指向的文件 ② 本 .dylib 同目录的 ida_lang.txt
//
// 调试：设环境变量 IDA_ZH_DEBUG=1 时，每个钩子首次命中会往 stderr 打一行。
//   进程退出时把统计写到 /tmp/ida_zh_stats.txt，未命中的原文写到
//   /tmp/ida_missing_translations_mac.txt（可直接补进词典）。
// ============================================================================

#include <dlfcn.h>
#include <mach-o/dyld.h>
#include <pthread.h>

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <mutex>
#include <set>
#include <string>
#include <unordered_map>

// ─────────────────────────────────────────────────────────────────────────
// 一、Qt6 的 QString 内存布局（24 字节，已由 QtCore 反汇编确认字段偏移）
//     QStringPrivate { QArrayData* d; char16_t* ptr; qsizetype size; }
//     我们只读 ptr/size，不碰引用计数头 d。
// ─────────────────────────────────────────────────────────────────────────
struct QString {
    void     *d;     // +0  引用计数/分配头（透传，不动）
    char16_t *ptr;   // +8  UTF-16 数据指针（可能不以 NUL 结尾，必须配合 size）
    long long size;  // +16 字符数（char16_t 个数），qsizetype = int64
};
static_assert(sizeof(QString) == 24, "QString 必须正好 24 字节（Qt6 arm64）");

// ─────────────────────────────────────────────────────────────────────────
// 二、Qt 构造函数：QString::fromUtf8(QByteArrayView)
//     本库已直接链接 QtCore，所以用 asm-label 直接声明该符号并调用，
//     不走 dlsym（之前 dlsym 在构造期返回 0，导致返回坏 QString 崩溃）。
//     ★ 字段顺序很关键：Qt6 的 QByteArrayView 是
//          { qsizetype m_size;  const char* m_data; }   —— size 在前！
//     16 字节，arm64 按值传 → 拆进 x0(size)/x1(data)。所以这里参数顺序必须写成
//     (size, data)。之前写成 (data, size) 导致把字符串长度当指针解引用而段错误。
// ─────────────────────────────────────────────────────────────────────────
extern "C" QString qt_QString_fromUtf8(long long size, const char *data)
    asm("__ZN2QT7QString8fromUtf8ENS_14QByteArrayViewE");

// 由一个 UTF-8 C 串造出一个新的 QString（引用计数=1）。
// 返回值按值传出，编译器用 x8 间接返回，与 Qt 的 ABI 完全一致。
static QString make_qstring(const char *utf8) {
    return qt_QString_fromUtf8(static_cast<long long>(std::strlen(utf8)), utf8);
}

// 把传入的 QString 的 UTF-16 文本转成 UTF-8 std::string（只读 ptr/size）。
static std::string qstring_to_utf8(const QString *s) {
    if (!s || s->size <= 0 || !s->ptr) return std::string();
    const char16_t *u = s->ptr;
    long long n = s->size;
    std::string out;
    out.reserve(static_cast<size_t>(n) + (n / 2));
    for (long long i = 0; i < n; ++i) {
        unsigned int cp = u[i];
        // UTF-16 代理对合成一个码点
        if (cp >= 0xD800 && cp <= 0xDBFF && i + 1 < n) {
            unsigned int lo = u[i + 1];
            if (lo >= 0xDC00 && lo <= 0xDFFF) {
                cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                ++i;
            }
        }
        if (cp < 0x80) {
            out.push_back(static_cast<char>(cp));
        } else if (cp < 0x800) {
            out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        } else if (cp < 0x10000) {
            out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        } else {
            out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        }
    }
    return out;
}

// ─────────────────────────────────────────────────────────────────────────
// 三、词典加载（识别 C 转义；从 IDA_LANG 或本库同目录的 ida_lang.txt 读）
// ─────────────────────────────────────────────────────────────────────────
// 解析一个转义序列，把结果字符追加到 dst，返回在 src 上消耗的字节数。
static int parse_escape(const char *src, std::string &dst) {
    if (src[0] != '\\') { dst.push_back(src[0]); return 1; }
    switch (src[1]) {
    case 'n':  dst.push_back('\n'); return 2;
    case 't':  dst.push_back('\t'); return 2;
    case 'r':  dst.push_back('\r'); return 2;
    case '\\': dst.push_back('\\'); return 2;
    case '"':  dst.push_back('"');  return 2;
    case '\0': dst.push_back('\\'); return 1;  // 行尾孤立反斜杠，原样留
    default:   dst.push_back(src[1]); return 2; // 其它 \x 取 x
    }
}

// 从 line[pos] 处提取一个  L"...."  字符串字面量的内容，pos 推进到结束引号之后。
static std::string extract_lstring(const std::string &line, size_t &pos) {
    while (pos < line.size() && (line[pos] == ' ' || line[pos] == '\t')) pos++;
    if (pos < line.size() && line[pos] == 'L') pos++;      // 跳过前缀 L
    if (pos >= line.size() || line[pos] != '"') return "";  // 不是字符串
    pos++;                                                  // 跳过开引号
    std::string out;
    while (pos < line.size() && line[pos] != '"') {
        if (line[pos] == '\\' && pos + 1 < line.size())
            pos += parse_escape(line.c_str() + pos, out);
        else
            out.push_back(line[pos++]);
    }
    if (pos < line.size()) pos++;                           // 跳过闭引号
    return out;
}

// 取本 .dylib 所在目录（用于回退查找同目录的 ida_lang.txt）
static std::string dylib_dir() {
    Dl_info info {};
    if (dladdr(reinterpret_cast<void *>(&dylib_dir), &info) == 0 || !info.dli_fname)
        return "";
    std::string path(info.dli_fname);
    size_t slash = path.rfind('/');
    return slash == std::string::npos ? "" : path.substr(0, slash);
}

// 真正读文件、构造并返回一张词典（堆上分配，进程生命周期内不释放）。
static std::unordered_map<std::string, std::string> *load_dict() {
    auto *table = new std::unordered_map<std::string, std::string>();
    const char *env_path = getenv("IDA_LANG");
    std::string bundled = dylib_dir() + "/ida_lang.txt";
    const char *candidates[] = {
        (env_path && env_path[0]) ? env_path : nullptr,
        bundled.empty() ? nullptr : bundled.c_str(),
    };

    std::ifstream file;
    const char *used = nullptr;
    for (const char *c : candidates) {
        if (!c) continue;
        file.open(c);
        if (file.is_open()) { used = c; break; }
    }
    if (!file.is_open()) {
        std::fprintf(stderr, "[ida_zh] 未找到 ida_lang.txt（设 IDA_LANG 指定路径）\n");
        return table;
    }

    std::string line;
    int count = 0;
    while (std::getline(file, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();  // 去掉 CRLF 的 \r
        if (line.empty() || line[0] == '#') continue;               // 空行/注释
        size_t pos = 0;
        std::string key = extract_lstring(line, pos);
        while (pos < line.size() && (line[pos] == ' ' || line[pos] == ',' || line[pos] == '\t'))
            pos++;
        std::string val = extract_lstring(line, pos);
        // 只收“有原文、有译文、且译文与原文不同”的条目（src==dst 是有意保留的英文，
        // 收进来也无害，但跳过可省内存、也避免无谓的 QString 构造）。
        if (!key.empty() && !val.empty() && key != val) {
            (*table)[key] = val;
            count++;
        }
    }
    std::fprintf(stderr, "[ida_zh] 从 %s 载入 %d 条翻译\n", used, count);
    return table;
}

// ★ 用【函数内静态】拿词典：首次调用时才构造+加载，且 C++ 保证“构造先于使用、
//    且只构造一次、线程安全”。这样即便本库的 constructor 比命名空间级静态对象的
//    动态初始化更早运行，也不会碰到“尚未构造、内存是垃圾”的容器
//    —— 之前的 SIGABRT 正是栽在“构造函数里往未初始化的命名空间静态 map 插入”。
static const std::unordered_map<std::string, std::string> &dict() {
    static const std::unordered_map<std::string, std::string> *table = load_dict();
    return *table;
}

// ─────────────────────────────────────────────────────────────────────────
// 四、埋点：命中/未命中统计 + 未命中原文收集（用于验证与后续补词典）
// ─────────────────────────────────────────────────────────────────────────
static std::atomic<long> g_hit_translate { 0 };
static std::atomic<long> g_hit_setter    { 0 };
static std::atomic<long> g_miss          { 0 };
static bool g_debug = false;

static std::set<std::string> g_missing;
static std::mutex g_missing_mu;

static void record_missing(const std::string &s) {
    if (s.size() <= 1) return;                 // 单字符/空串噪音太多，忽略
    std::lock_guard<std::mutex> lk(g_missing_mu);
    g_missing.insert(s);
}

// 诊断用：把前若干条命中追加到文件，便于在 GUI 进程里确认翻译确实发生
//（不依赖 stderr / 退出码 / 截图权限）。封顶防止日志爆量。
static std::atomic<int> g_hitlog_n { 0 };
static void log_hit(const char *kind, const char *src, const char *dst) {
    if (!g_debug) return;                       // 仅 IDA_ZH_DEBUG=1 时记录
    int n = g_hitlog_n.fetch_add(1);
    if (n >= 300) return;
    std::ofstream f("/tmp/ida_zh_hits.log", std::ios::app);
    if (f.is_open()) f << kind << "  " << src << "  =>  " << dst << "\n";
}

// ─────────────────────────────────────────────────────────────────────────
// 五、控件设置器用的“翻译后 QString 缓存”
//     setText 等接收的是 const QString&（即一个 QString 指针）。命中后我们需要
//     提供一个【中文 QString】的地址传进去。为避免每次都新建（会泄漏引用计数），
//     把每个原文对应的中文 QString 缓存起来，全程只构造一次。
//     （unordered_map 的节点地址稳定，插入不会让已有元素指针失效，可安全取址。）
// ─────────────────────────────────────────────────────────────────────────
static std::unordered_map<std::string, QString> g_qcache;
static std::mutex g_qcache_mu;

// 给一个传入的英文 QString：命中词典则返回缓存的中文 QString 指针，否则原样返回。
static const QString *maybe_translate(const QString *in) {
    if (!in || in->size <= 0 || !in->ptr) return in;
    std::string utf8 = qstring_to_utf8(in);
    const auto &m = dict();
    auto it = m.find(utf8);
    if (it == m.end()) { g_miss++; record_missing(utf8); return in; }

    std::lock_guard<std::mutex> lk(g_qcache_mu);
    auto c = g_qcache.find(utf8);
    if (c == g_qcache.end())
        c = g_qcache.emplace(utf8, make_qstring(it->second.c_str())).first;
    g_hit_setter++;
    log_hit("setter", utf8.c_str(), it->second.c_str());
    if (g_debug)
        std::fprintf(stderr, "[ida_zh][setter] %s\n", utf8.c_str());
    return &c->second;
}

// translate() 路径：直接拿到 const char* 原文，命中则按值返回新建的中文 QString。
static bool translate_src(const char *src, QString *out) {
    if (!src || !src[0]) return false;
    const auto &m = dict();
    auto it = m.find(src);
    if (it == m.end()) { g_miss++; record_missing(src); return false; }
    g_hit_translate++;
    log_hit("tr", src, it->second.c_str());
    if (g_debug)
        std::fprintf(stderr, "[ida_zh][tr] %s\n", src);
    *out = make_qstring(it->second.c_str());
    return true;
}

// ─────────────────────────────────────────────────────────────────────────
// 六、DYLD_INTERPOSE 宏 + 原始 Qt 符号的 asm-label 声明
//     asm() 标签是【逐字】的 Mach-O 符号名（clang 不会自动补下划线），所以要写
//     和 nm 里完全一致的【两个前导下划线】__ZN2QT...（注意这跟 dlsym 规则相反：
//     dlsym 要去掉一个下划线，写 _ZN2QT...）。
// ─────────────────────────────────────────────────────────────────────────
#define DYLD_INTERPOSE(_replacement, _replacee)                                \
    __attribute__((used, section("__DATA,__interpose")))                       \
    static const struct {                                                      \
        const void *replacement;                                               \
        const void *replacee;                                                  \
    } _interpose_##_replacement = {                                            \
        (const void *)(unsigned long)&_replacement,                            \
        (const void *)(unsigned long)&_replacee                                \
    };

extern "C" {
// translate 两兄弟（按值返回 QString）
QString real_QCoreApplication_translate(const char *, const char *, const char *, int)
    asm("__ZN2QT16QCoreApplication9translateEPKcS2_S2_i");
QString real_QTranslator_translate(const void *, const char *, const char *, const char *, int)
    asm("__ZNK2QT11QTranslator9translateEPKcS2_S2_i");

// 控件设置器（返回 void；QString 以 const 引用=指针传入）
void real_QAction_setText      (void *, const QString *) asm("__ZN2QT7QAction7setTextERKNS_7QStringE");
void real_QLabel_setText       (void *, const QString *) asm("__ZN2QT6QLabel7setTextERKNS_7QStringE");
void real_QAbstractButton_setText(void *, const QString *) asm("__ZN2QT15QAbstractButton7setTextERKNS_7QStringE");
void real_QMenu_setTitle       (void *, const QString *) asm("__ZN2QT5QMenu8setTitleERKNS_7QStringE");
void real_QGroupBox_setTitle   (void *, const QString *) asm("__ZN2QT9QGroupBox8setTitleERKNS_7QStringE");
void real_QWidget_setWindowTitle(void *, const QString *) asm("__ZN2QT7QWidget14setWindowTitleERKNS_7QStringE");
void real_QWidget_setToolTip   (void *, const QString *) asm("__ZN2QT7QWidget10setToolTipERKNS_7QStringE");
void real_QAction_setToolTip   (void *, const QString *) asm("__ZN2QT7QAction10setToolTipERKNS_7QStringE");
void real_QMessageBox_setText  (void *, const QString *) asm("__ZN2QT11QMessageBox7setTextERKNS_7QStringE");
void real_QLineEdit_setPlaceholderText(void *, const QString *) asm("__ZN2QT9QLineEdit18setPlaceholderTextERKNS_7QStringE");
// 带额外参数的两个
void real_QTabWidget_setTabText(void *, int, const QString *) asm("__ZN2QT10QTabWidget10setTabTextEiRKNS_7QStringE");
void real_QStatusBar_showMessage(void *, const QString *, int) asm("__ZN2QT10QStatusBar11showMessageERKNS_7QStringEi");

// 构造时带文本的路径（绕过 setText / fromUtf8，多为 QStringLiteral）：
// 选项卡 addTab、按钮/复选框/标签的“带文本构造函数”。这些也是只动控件标签，安全。
int  real_QTabWidget_addTab(void *, void *, const QString *) asm("__ZN2QT10QTabWidget6addTabEPNS_7QWidgetERKNS_7QStringE");
int  real_QTabBar_addTab(void *, const QString *) asm("__ZN2QT7QTabBar6addTabERKNS_7QStringE");
void real_QPushButton_ctor(void *, const QString *, void *) asm("__ZN2QT11QPushButtonC1ERKNS_7QStringEPNS_7QWidgetE");
void real_QCheckBox_ctor(void *, const QString *, void *) asm("__ZN2QT9QCheckBoxC1ERKNS_7QStringEPNS_7QWidgetE");
void real_QLabel_ctor(void *, const QString *, void *, unsigned int) asm("__ZN2QT6QLabelC1ERKNS_7QStringEPNS_7QWidgetENS_6QFlagsINS_2Qt10WindowTypeEEE");
}

// ─────────────────────────────────────────────────────────────────────────
// 七、替换函数实现
// ─────────────────────────────────────────────────────────────────────────
// QString::fromUtf8(QByteArrayView) —— 兜底拦截（带安全护栏）。
// 很多界面文字（如 Teams 菜单、已加载的调试器名、QPushButton 文本）既不走
// translate() 也不走 setText()，而是直接由 fromUtf8 构造后塞进控件。这里兜底翻译。
// ★ 安全护栏（避免污染被逆向的二进制内容）：
//   - 只处理【短串】(<= 64 字节)：UI 标签都很短；被分析二进制里的字符串/反汇编
//     文本通常更长，超长直接放行不查词典，既保护内容、又省去热路径开销。
//   - 只翻译【精确命中词典】的串：词典是一份人工整理的“界面文案”表，命中即视为 UI。
//   - 短的二进制字符串若恰好等于某条词典原文，仍可能被换成中文（仅出现在字符串/
//     反汇编视图里，属可接受的小代价）。
static std::atomic<long> g_hit_fromutf8 { 0 };
static thread_local bool g_in_frombytes = false;  // 递归护栏（fromUtf8/fromLatin1 共用）
static bool g_fromutf8_off = false;               // IDA_ZH_NO_FROMUTF8=1 时关闭兜底

// 真 fromLatin1（ASCII 串常走它；asm-label 直接调，签名同 fromUtf8）
extern "C" QString qt_QString_fromLatin1(long long size, const char *data)
    asm("__ZN2QT7QString10fromLatin1ENS_14QByteArrayViewE");

// 共用：短串(<=64) + 精确命中词典 → 把中文写进 out 返回 true。
// 用真 fromUtf8 造中文；g_in_frombytes 兜底保证绝不递归（dyld interpose 本就不会把
// “本库自身对被拦截符号的调用”再派回本函数，这里再加一道保险）。
static bool translate_bytes(long long size, const char *data, QString *out, const char *tag) {
    if (g_fromutf8_off || g_in_frombytes || !data || size <= 0 || size > 64) return false;
    std::string s(data, static_cast<size_t>(size));
    const auto &m = dict();
    auto it = m.find(s);
    if (it == m.end()) return false;
    g_hit_fromutf8++;
    log_hit(tag, s.c_str(), it->second.c_str());
    g_in_frombytes = true;
    *out = make_qstring(it->second.c_str());
    g_in_frombytes = false;
    return true;
}
static QString my_QString_fromUtf8(long long size, const char *data) {
    QString out;
    if (translate_bytes(size, data, &out, "utf8")) return out;
    return qt_QString_fromUtf8(size, data);   // 未命中/超长/递归中：原样放行
}
static QString my_QString_fromLatin1(long long size, const char *data) {
    QString out;
    if (translate_bytes(size, data, &out, "lat1")) return out;
    return qt_QString_fromLatin1(size, data);
}

// translate（静态函数，无 this）
static QString my_QCoreApplication_translate(const char *context, const char *sourceText,
                                             const char *disambiguation, int n) {
    QString out;
    if (translate_src(sourceText, &out)) return out;
    return real_QCoreApplication_translate(context, sourceText, disambiguation, n);
}
// QTranslator::translate（const 成员函数，this 在 x0，必须原样透传 self）
static QString my_QTranslator_translate(const void *self, const char *context,
                                        const char *sourceText, const char *disambiguation, int n) {
    QString out;
    if (translate_src(sourceText, &out)) return out;
    return real_QTranslator_translate(self, context, sourceText, disambiguation, n);
}

// 一组只有 (self, const QString&) 形状的设置器，用宏批量生成
#define SETTER1(MYNAME, REAL)                                                   \
    static void MYNAME(void *self, const QString *s) {                         \
        REAL(self, maybe_translate(s));                                        \
    }
SETTER1(my_QAction_setText,        real_QAction_setText)
SETTER1(my_QLabel_setText,         real_QLabel_setText)
SETTER1(my_QAbstractButton_setText,real_QAbstractButton_setText)
SETTER1(my_QMenu_setTitle,         real_QMenu_setTitle)
SETTER1(my_QGroupBox_setTitle,     real_QGroupBox_setTitle)
SETTER1(my_QWidget_setWindowTitle, real_QWidget_setWindowTitle)
SETTER1(my_QWidget_setToolTip,     real_QWidget_setToolTip)
SETTER1(my_QAction_setToolTip,     real_QAction_setToolTip)
SETTER1(my_QMessageBox_setText,    real_QMessageBox_setText)
SETTER1(my_QLineEdit_setPlaceholderText, real_QLineEdit_setPlaceholderText)

// 带额外参数的两个，单独写
static void my_QTabWidget_setTabText(void *self, int index, const QString *s) {
    real_QTabWidget_setTabText(self, index, maybe_translate(s));
}
static void my_QStatusBar_showMessage(void *self, const QString *s, int timeout) {
    real_QStatusBar_showMessage(self, maybe_translate(s), timeout);
}

// 构造时带文本的路径
static int my_QTabWidget_addTab(void *self, void *page, const QString *s) {
    return real_QTabWidget_addTab(self, page, maybe_translate(s));
}
static int my_QTabBar_addTab(void *self, const QString *s) {
    return real_QTabBar_addTab(self, maybe_translate(s));
}
static void my_QPushButton_ctor(void *self, const QString *s, void *parent) {
    real_QPushButton_ctor(self, maybe_translate(s), parent);
}
static void my_QCheckBox_ctor(void *self, const QString *s, void *parent) {
    real_QCheckBox_ctor(self, maybe_translate(s), parent);
}
static void my_QLabel_ctor(void *self, const QString *s, void *parent, unsigned int f) {
    real_QLabel_ctor(self, maybe_translate(s), parent, f);
}

// ─────────────────────────────────────────────────────────────────────────
// 八、登记 interpose 对（dyld 据此把对原始函数的调用改派给我们的函数）
// ─────────────────────────────────────────────────────────────────────────
DYLD_INTERPOSE(my_QString_fromUtf8,           qt_QString_fromUtf8)
DYLD_INTERPOSE(my_QString_fromLatin1,         qt_QString_fromLatin1)
DYLD_INTERPOSE(my_QCoreApplication_translate, real_QCoreApplication_translate)
DYLD_INTERPOSE(my_QTranslator_translate,      real_QTranslator_translate)
DYLD_INTERPOSE(my_QAction_setText,            real_QAction_setText)
DYLD_INTERPOSE(my_QLabel_setText,             real_QLabel_setText)
DYLD_INTERPOSE(my_QAbstractButton_setText,    real_QAbstractButton_setText)
DYLD_INTERPOSE(my_QMenu_setTitle,             real_QMenu_setTitle)
DYLD_INTERPOSE(my_QGroupBox_setTitle,         real_QGroupBox_setTitle)
DYLD_INTERPOSE(my_QWidget_setWindowTitle,     real_QWidget_setWindowTitle)
DYLD_INTERPOSE(my_QWidget_setToolTip,         real_QWidget_setToolTip)
DYLD_INTERPOSE(my_QAction_setToolTip,         real_QAction_setToolTip)
DYLD_INTERPOSE(my_QMessageBox_setText,        real_QMessageBox_setText)
DYLD_INTERPOSE(my_QLineEdit_setPlaceholderText, real_QLineEdit_setPlaceholderText)
DYLD_INTERPOSE(my_QTabWidget_setTabText,      real_QTabWidget_setTabText)
DYLD_INTERPOSE(my_QStatusBar_showMessage,     real_QStatusBar_showMessage)
DYLD_INTERPOSE(my_QTabWidget_addTab,          real_QTabWidget_addTab)
DYLD_INTERPOSE(my_QTabBar_addTab,             real_QTabBar_addTab)
DYLD_INTERPOSE(my_QPushButton_ctor,           real_QPushButton_ctor)
DYLD_INTERPOSE(my_QCheckBox_ctor,             real_QCheckBox_ctor)
DYLD_INTERPOSE(my_QLabel_ctor,                real_QLabel_ctor)

// ─────────────────────────────────────────────────────────────────────────
// 九、生命周期：加载时预热词典；退出时落统计与未命中清单
// ─────────────────────────────────────────────────────────────────────────
// 诊断用：把构造函数执行情况追加进文件，不受 stderr 重定向/re-exec 影响。
#include <unistd.h>
static void diag_marker(const char *tag) {
    std::ofstream f("/tmp/ida_zh_ctor.log", std::ios::app);
    if (!f.is_open()) return;
    char exe[1024]; uint32_t sz = sizeof(exe);
    if (_NSGetExecutablePath(exe, &sz) != 0) exe[0] = '\0';
    const char *ins = getenv("DYLD_INSERT_LIBRARIES");
    f << tag << " pid=" << (long)getpid() << " ppid=" << (long)getppid()
      << " exe=" << exe
      << " fromUtf8=" << (void *)&qt_QString_fromUtf8
      << " DYLD_INSERT=" << (ins ? ins : "(已被清空)") << "\n";
}

__attribute__((constructor))
static void on_load() {
    const char *dbg = getenv("IDA_ZH_DEBUG");
    g_debug = (dbg && dbg[0] == '1');
    // ★ 默认【保守模式】：fromUtf8/fromLatin1 兜底【关闭】，绝不碰被分析二进制内容
    //   （字符串窗口/函数列表里的英文不会被误翻）。控件级 hook 始终开启、天然安全。
    //   设 IDA_ZH_FULL=1 才开启兜底 → 界面覆盖最全，但二进制内容里恰好等于某 UI 词的
    //   英文也可能被显示成中文（仅显示层，不影响地址/字节/分析）。
    const char *full = getenv("IDA_ZH_FULL");
    g_fromutf8_off = !(full && full[0] == '1');
    if (g_debug) diag_marker("ctor");    // 仅调试：文件标记构造函数在本进程跑过
    dict();   // 预热（顺带在 stderr 打印载入条数，便于确认注入成功）
    std::fprintf(stderr, "[ida_zh] 注入就绪（fromUtf8=%p, debug=%d）\n",
                 (void *)&qt_QString_fromUtf8, (int)g_debug);
}

__attribute__((destructor))
static void on_unload() {
    // 统计
    std::ofstream st("/tmp/ida_zh_stats.txt");
    if (st.is_open()) {
        st << "translate 命中: " << g_hit_translate.load() << "\n";
        st << "setter    命中: " << g_hit_setter.load() << "\n";
        st << "未命中(去重前累计): " << g_miss.load() << "\n";
        st << "未命中去重后条数: " << g_missing.size() << "\n";
    }
    // 未命中原文（可直接补进词典）
    if (!g_missing.empty()) {
        std::ofstream f("/tmp/ida_missing_translations_mac.txt");
        f << "# IDA 未命中的原文（右侧译文待填后可追加进 ida_lang.txt）\n";
        for (const auto &s : g_missing) {
            std::string e;
            for (char c : s) {
                if (c == '"' || c == '\\') e.push_back('\\');
                e.push_back(c);
            }
            f << "L\"" << e << "\",L\"" << e << "\",\n";
        }
    }
}

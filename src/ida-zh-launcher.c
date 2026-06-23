// ============================================================================
// IDA 9.3 中文 包装器壳 —— 编译型启动器（Mach-O）
// ----------------------------------------------------------------------------
// 作为壳 .app 的 CFBundleExecutable。双击壳 → LaunchServices 运行本程序 →
// 本程序用 `/usr/bin/open --env ...` 把汉化 hook 与词典作为环境变量、经正常
// app 方式拉起官方原版 IDA（这样 IDA 不会重新拉起自己、DYLD_* 得以保留）。
//
// 为什么不直接 exec ida：裸启动 ida 会触发它经 LaunchServices 重新拉起、剥掉
// DYLD_* → 注入失效。必须走 `open --env`。
// 为什么用编译型而非 shell 脚本当 app 可执行体：近年 macOS 的 LaunchServices
// 对“脚本充当 .app 主程序”有时拒绝（报 -10669），换成 Mach-O 最稳。
// ============================================================================
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libgen.h>
#include <sys/stat.h>
#include <copyfile.h>
#include <mach-o/dyld.h>

int main(int argc, char *argv[]) {
    // 1) 取本可执行体绝对路径：.../IDA Professional 9.3 中文.app/Contents/MacOS/ida-zh-launcher
    char exe[4096];
    uint32_t sz = sizeof(exe);
    if (_NSGetExecutablePath(exe, &sz) != 0) {
        fprintf(stderr, "无法取得自身路径\n");
        return 1;
    }
    // 2) 由它推出 Contents 目录：MacOS 的上一级
    char macdir[4096];   snprintf(macdir, sizeof(macdir), "%s", dirname(exe));     // …/Contents/MacOS
    char contents[4096]; snprintf(contents, sizeof(contents), "%s", dirname(macdir)); // …/Contents

    // 3) 拼出 Resources 下的 hook 库与词典
    char hook[4200], lang[4200];
    snprintf(hook, sizeof(hook), "%s/Resources/ida_lang_hook.dylib", contents);
    snprintf(lang, sizeof(lang), "%s/Resources/ida_lang.txt", contents);

    // 3.5) ★关键★ DYLD_INSERT_LIBRARIES 以【冒号】分隔多个路径；若本壳所在目录名里含冒号
    //      （如 "(macOS:Apple_Silicon)"），注入路径会被劈成两段无效路径，dyld 直接 halt。
    //      为此：当 hook 路径含冒号时，把它复制到一个【无冒号】的临时路径再注入。
    //      （词典 IDA_LANG 走的是 fopen，冒号无所谓，无需复制。）
    if (strchr(hook, ':') != NULL) {
        const char *td = getenv("TMPDIR");
        char base[4096];
        if (td && td[0] && strchr(td, ':') == NULL)
            snprintf(base, sizeof(base), "%s/ida-zh", td);
        else
            snprintf(base, sizeof(base), "/tmp/ida-zh");
        mkdir(base, 0755);                                   // 已存在则忽略
        char safe[4200];
        snprintf(safe, sizeof(safe), "%s/ida_lang_hook.dylib", base);
        // 复制数据（Mach-O 内嵌的 ad-hoc 签名随之保留）；成功则改用无冒号路径
        if (copyfile(hook, safe, NULL, COPYFILE_DATA | COPYFILE_UNLINK) == 0)
            snprintf(hook, sizeof(hook), "%s", safe);
    }

    // 4) 组装 open 的环境变量参数值
    char envHook[4300], envLang[4300];
    snprintf(envHook, sizeof(envHook), "DYLD_INSERT_LIBRARIES=%s", hook);
    snprintf(envLang, sizeof(envLang), "IDA_LANG=%s", lang);

    // 4.5) 若本壳的 Resources 下有标记文件 .full，则开启“全量覆盖”模式
    //      （额外注入 IDA_ZH_FULL=1，启用 fromUtf8 兜底）。默认（无标记）= 保守模式。
    char marker[4300];
    snprintf(marker, sizeof(marker), "%s/Resources/.full", contents);
    int full_mode = (access(marker, F_OK) == 0);

    // 5) 构造命令行：
    //    /usr/bin/open -n --env <hook> --env <lang> [--env IDA_ZH_FULL=1] -a "<原版IDA>" [文件...]
    const char *real_app = "/Applications/IDA Professional 9.3.app";
    // argv 向量：固定最多 10 个 + 透传参数(argc-1) + NULL
    int base = 10;
    char **args = (char **)calloc(base + argc, sizeof(char *));
    int i = 0;
    args[i++] = (char *)"/usr/bin/open";
    args[i++] = (char *)"-n";
    args[i++] = (char *)"--env";
    args[i++] = envHook;
    args[i++] = (char *)"--env";
    args[i++] = envLang;
    if (full_mode) {
        args[i++] = (char *)"--env";
        args[i++] = (char *)"IDA_ZH_FULL=1";
    }
    args[i++] = (char *)"-a";
    args[i++] = (char *)real_app;
    for (int a = 1; a < argc; a++) args[i++] = argv[a];  // 透传双击的 .i64/.idb
    args[i] = NULL;

    // 6) 用 open 替换本进程映像
    execv("/usr/bin/open", args);
    // 走到这说明 execv 失败
    perror("execv /usr/bin/open 失败");
    return 1;
}

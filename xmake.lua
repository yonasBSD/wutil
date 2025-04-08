add_rules("mode.debug", "mode.release")

set_policy("build.sanitizer.address", true)
set_policy("build.sanitizer.undefined", true)
add_rules("plugin.compile_commands.autoupdate")
add_cflags("-Wall -Wextra -Wpedantic -Wshadow -Wunused -g")

target("library")
    set_kind("static")
    add_files("src/lib/*.c")

target("wutil")
    set_kind("binary")
    add_files("src/cli.c", "src/usage.c")
    add_deps("library")

add_rules("mode.debug", "mode.release")

set_policy("build.sanitizer.address", true)
set_policy("build.sanitizer.undefined", true)
add_rules("plugin.compile_commands.autoupdate")
add_cxxflags("-Wall -Wextra -Wpedantic -Wshadow -Wunused -g")

target("wutil")
    set_kind("binary")
    add_files("src/*.c")

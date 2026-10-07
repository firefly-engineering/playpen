fn main() {
    // Everything playpen takes from its environment and working directory is read once, here, and
    // handed to the launch as inputs.
    let var = std::env::var_os;
    let host = playpen::launch::Host {
        cwd: std::env::current_dir(),
        state: playpen::record::state_dir(var("XDG_STATE_HOME"), var("HOME")),
        policies: playpen::policy::SearchPath::new(var("XDG_CONFIG_HOME"), var("HOME")),
        profile: var(playpen::select::ENV),
        // Resolved: macOS reports the path playpen was invoked through, which is the shim link
        // where there is one, and it is the binary behind it that must be shown unwritable.
        executable: std::env::current_exe().and_then(std::fs::canonicalize),
        env: std::env::vars_os().collect(),
        floor: playpen::floor::dedicated(var(playpen::floor::FLOOR_ENV)),
    };
    let status = playpen::launch::main(
        std::env::args_os(),
        host,
        playpen::mechanism::Mechanism::probe,
        playpen::trace::open,
    );
    std::process::exit(status);
}

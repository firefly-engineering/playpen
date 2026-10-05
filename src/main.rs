fn main() {
    // Everything playpen takes from its environment and working directory is read once, here, and
    // handed to the launch as inputs.
    let var = std::env::var_os;
    let host = playpen::launch::Host {
        cwd: std::env::current_dir(),
        state: playpen::record::state_dir(var("XDG_STATE_HOME"), var("HOME")),
        policies: playpen::policy::SearchPath::new(var("XDG_CONFIG_HOME"), var("HOME")),
        profile: var(playpen::select::ENV),
        executable: std::env::current_exe(),
        env: std::env::vars_os().collect(),
    };
    let status = playpen::launch::main(
        std::env::args_os(),
        host,
        playpen::mechanism::Mechanism::probe,
    );
    std::process::exit(status);
}

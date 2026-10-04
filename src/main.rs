fn main() {
    // The caller's working directory and playpen's state directory are read once, here, and handed
    // to the launch as inputs.
    let state =
        playpen::record::state_dir(std::env::var_os("XDG_STATE_HOME"), std::env::var_os("HOME"));
    let status = playpen::launch::main(
        std::env::args_os(),
        std::env::current_dir(),
        state,
        playpen::mechanism::Mechanism::probe,
    );
    std::process::exit(status);
}

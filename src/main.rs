fn main() {
    // The caller's working directory is read once, here, and handed to the launch as an input.
    let status = playpen::launch::main(std::env::args_os(), std::env::current_dir());
    std::process::exit(status);
}

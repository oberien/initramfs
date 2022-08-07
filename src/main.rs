use initramfs::Initramfs;

fn main() {
    env_logger::init();
    let filename = match std::env::args().nth(1) {
        Some(filename) => filename,
        None => {
            eprintln!("Usage: <initramfs-file>");
            std::process::exit(1);
        }
    };
    let content = std::fs::read(filename).expect("can't read file");
    let initramfs = Initramfs::parse(&content).expect("parsing initramfs failed");
    for file in initramfs.archives.iter().flat_map(|archive| &archive.files) {
        println!("{}: {}", String::from_utf8_lossy(&file.filename), file.header.filesize);
    }
    let mut content2 = Vec::new();
    initramfs.write(&mut content2);
    println!("equal: {}", content == content2);
}

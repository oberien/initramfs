use initramfs::{Initramfs, MaybeRawArchive};

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
    let files = initramfs.archives.iter().filter_map(|archive| match archive {
        MaybeRawArchive::Parsed(archive) => Some(&archive.files),
        MaybeRawArchive::Raw(_) => None,
    }).flatten();
    for file in files {
        println!("{}: {}", String::from_utf8_lossy(&file.filename), file.header.filesize);
    }
    let mut content2 = Vec::new();
    initramfs.write(&mut content2);
    println!("equal: {}", content == content2);
}

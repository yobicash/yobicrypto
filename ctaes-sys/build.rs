extern crate cc;

fn main() {
    cc::Build::new()
        .file("ctaes/ctaes.c")
        .compile("ctaes")
}

use std::path::PathBuf;

fn main() {
    #[cfg(not(any(feature = "simple", feature = "robust")))]
    compile_error!("Please select the thash type by activating either the feature simple or robost.");
    #[cfg(all(feature = "simple", feature = "robust"))]
    compile_error!("Please select only one thash type by activating either the feature simple or robost.");

    #[cfg(not(any(feature = "sha2", feature = "shake", feature = "haraka")))]
    compile_error!("Please select the hash type by activating either the feature sha2, shake2 or haraka.");
    #[cfg(any(
        all(feature = "sha2", feature = "shake"),
        all(feature = "sha2", feature = "haraka"),
        all(feature = "shake", feature = "haraka")
    ))]
    compile_error!("Please select only one hash type by activating either the feature sha2, shake2 or haraka.");
    #[cfg(not(any(
        feature = "128f",
        feature = "128s",
        feature = "192s",
        feature = "192f",
        feature = "256s",
        feature = "256f",
    )))]
    compile_error!("Please select the hash size by activating either the feature 128f, 128s, 192s, 192f, 256s or 256f.");
    #[cfg(any(
        all(
            feature = "128f",
            feature = "128s",
        ),
        all(
            feature = "128f",
            feature = "192s",
        ),
        all(
            feature = "128f",
            feature = "192f",
        ),
        all(
            feature = "128f",
            feature = "256s",
        ),
        all(
            feature = "128f",
            feature = "256f",
        ),
        all(
            feature = "128s",
            feature = "192s",
        ),
        all(
            feature = "128s",
            feature = "192f",
        ),
        all(
            feature = "128s",
            feature = "256s",
        ),
        all(
            feature = "128s",
            feature = "256f",
        ),

        all(
            feature = "192s",
            feature = "192f",
        ),
        all(
            feature = "192s",
            feature = "256s",
        ),
        all(
            feature = "192s",
            feature = "256f",
        ),

        all(
            feature = "192f",
            feature = "256s",
        ),
        all(
            feature = "192f",
            feature = "256f",
        ),

        all(
            feature = "256s",
            feature = "256f",
        ),
    ))]
    compile_error!("Please select only one hash size by activating either the feature 128f, 128s, 192s, 192f, 256s or 256f.");

    let thash;
    #[cfg(feature = "simple")]
    {
        thash = "simple";
    }
    #[cfg(feature = "robust")]
    {
        thash = "robust";
    }
    let hash_algo;
    #[cfg(feature = "sha2")]
    {
        hash_algo = "sha2";
    }
    #[cfg(feature = "shake")]
    {
        hash_algo = "shake";
    }
    #[cfg(feature = "haraka")]
    {
        hash_algo = "haraka";
    }
    let size;
    #[cfg(feature = "128f")] { size = "128f"; }
    #[cfg(feature = "128s")] { size = "128s"; }
    #[cfg(feature = "192s")] { size = "192s"; }
    #[cfg(feature = "192f")] { size = "192f"; }
    #[cfg(feature = "256s")] { size = "256s"; }
    #[cfg(feature = "256f")] { size = "256f"; }
    let params = format!("sphincs-{hash_algo}-{size}");


    cc::Build::new()
        .define("THASH", thash)
        .define("PARAMS", params.as_str())
        .flags(&[
            "-Wall",
            "-Wextra",
            "-Wpedantic",
            "-O3",
            "-std=c99",
            "-Wconversion",
            "-Wmissing-prototypes"
        ])
        .files(&[
            "sphincsplus/ref/address.c",
            "sphincsplus/ref/randombytes.c",
            "sphincsplus/ref/merkle.c",
            "sphincsplus/ref/wots.c",
            "sphincsplus/ref/wotsx1.c",
            "sphincsplus/ref/utils.c",
            "sphincsplus/ref/utilsx1.c",
            "sphincsplus/ref/fors.c",
            "sphincsplus/ref/sign.c",

            #[cfg(feature = "shake")]
            "sphincsplus/ref/fips202.c",
            #[cfg(feature = "shake")]
            "sphincsplus/ref/hash_shake.c",
            #[cfg(all(feature = "shake", feature = "simple"))]
            "sphincsplus/ref/thash_shake_simple.c",
            #[cfg(all(feature = "shake", feature = "robust"))]
            "sphincsplus/ref/thash_shake_robust.c",

            #[cfg(feature = "haraka")]
            "sphincsplus/ref/haraka.c",
            #[cfg(feature = "haraka")]
            "sphincsplus/ref/hash_haraka.c",
            #[cfg(all(feature = "haraka", feature = "simple"))]
            "sphincsplus/ref/thash_haraka_simple.c",
            #[cfg(all(feature = "haraka", feature = "robust"))]
            "sphincsplus/ref/thash_haraka_robust.c",

            #[cfg(feature = "sha2")]
            "sphincsplus/ref/sha2.c",
            #[cfg(feature = "sha2")]
            "sphincsplus/ref/hash_sha2.c",
            #[cfg(all(feature = "sha2", feature = "simple"))]
            "sphincsplus/ref/thash_sha2_simple.c",
            #[cfg(all(feature = "sha2", feature = "robust"))]
            "sphincsplus/ref/thash_sha2_robust.c",
        ])
        .compile("sphincs");

    //println!("cargo:rustc-link-search=/path/to/lib");
    println!("cargo:rustc-link-lib=crypto");

    // The bindgen::Builder is the main entry point
    // to bindgen, and lets you build up options for
    // the resulting bindings.
    let bindings = bindgen::Builder::default()
        // The input header we would like to generate
        // bindings for.
        .clang_arg(format!("-DPARAMS={params}")) // define PARAMS
        .header("sphincsplus/ref/api.h")
        // Tell cargo to invalidate the built crate whenever any of the
        // included header files changed.
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        // Finish the builder and generate the bindings.
        .generate()
        // Unwrap the Result and panic on failure.
        .expect("Unable to generate bindings");

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let out_path = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");

}
use SafeRepo_CLI::database::db::VulnerabilityDB;
use SafeRepo_CLI::scaning::scan::{ScanOptions, scan_repo};
use SafeRepo_CLI::secure::security::SecurityManager;
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use std::fs;
use std::hint::black_box;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tempfile::TempDir;

fn empty_manager() -> SecurityManager {
    SecurityManager {
        db: VulnerabilityDB::new(),
    }
}

fn write_manifest_fixtures(root: &Path) -> [PathBuf; 3] {
    let cargo_lock = root.join("Cargo.lock");
    let package_lock = root.join("package-lock.json");
    let requirements = root.join("requirements.txt");

    fs::write(
        &cargo_lock,
        r#"version = 3

[[package]]
name = "serde"
version = "1.0.0"

[[package]]
name = "toml"
version = "0.8.0"
"#,
    )
    .expect("Impossible d'ecrire Cargo.lock");
    fs::write(
        &package_lock,
        r#"{
  "lockfileVersion": 3,
  "packages": {
    "": {"name": "fixture", "version": "1.0.0"},
    "node_modules/express": {"version": "4.17.1"},
    "node_modules/lodash": {"version": "4.17.21"}
  }
}"#,
    )
    .expect("Impossible d'ecrire package-lock.json");
    fs::write(
        &requirements,
        "requests==2.31.0\nnumpy==1.26.0\nflask==3.0.0\n",
    )
    .expect("Impossible d'ecrire requirements.txt");

    [cargo_lock, package_lock, requirements]
}

fn create_scan_fixture(directory_count: usize) -> TempDir {
    let temp_dir = TempDir::new().expect("Impossible de creer le repertoire temporaire");
    fs::write(
        temp_dir.path().join("Cargo.toml"),
        "[package]\nname = \"benchmark-fixture\"\nversion = \"0.1.0\"\n",
    )
    .expect("Impossible d'ecrire Cargo.toml");

    for index in 0..directory_count {
        let directory = temp_dir.path().join(format!("project-{index}"));
        fs::create_dir(&directory).expect("Impossible de creer le sous-repertoire");
        fs::write(
            directory.join("Cargo.toml"),
            "[package]\nname = \"nested-fixture\"\nversion = \"0.1.0\"\n",
        )
        .expect("Impossible d'ecrire le manifeste imbrique");
    }

    temp_dir
}

fn bench_production_parsers(c: &mut Criterion) {
    let temp_dir = TempDir::new().expect("Impossible de creer le repertoire temporaire");
    let manifest_paths = write_manifest_fixtures(temp_dir.path());
    let manager = empty_manager();
    let mut group = c.benchmark_group("production_parsing");
    group.measurement_time(Duration::from_secs(1));

    for path in manifest_paths {
        let name = path
            .file_name()
            .and_then(|value| value.to_str())
            .expect("Nom de fixture invalide")
            .replace('.', "_");
        group.bench_function(name, |benchmark| {
            benchmark.iter(|| {
                manager
                    .analyze_file(black_box(&path))
                    .expect("Le parsing de production doit reussir")
            })
        });
    }

    group.finish();
}

fn bench_production_scan(c: &mut Criterion) {
    let temp_dir = create_scan_fixture(40);
    let manager = empty_manager();
    let mut group = c.benchmark_group("production_scan");
    group.measurement_time(Duration::from_secs(1));

    for threads in [Some(1), Some(4)] {
        let label = format!("threads_{}", threads.unwrap());
        let options = ScanOptions {
            threads,
            database_path: None,
            ..ScanOptions::default()
        };
        group.bench_with_input(
            BenchmarkId::new("scan_repo", label),
            &options,
            |benchmark, options| {
                benchmark.iter(|| {
                    scan_repo(black_box(temp_dir.path()), &manager, options)
                        .expect("Le scan de production doit reussir")
                })
            },
        );
    }

    group.finish();
}

fn bench_production_throughput(c: &mut Criterion) {
    let temp_dir = create_scan_fixture(100);
    let manager = empty_manager();
    let options = ScanOptions {
        threads: Some(4),
        database_path: None,
        ..ScanOptions::default()
    };
    let mut group = c.benchmark_group("production_throughput");
    group.measurement_time(Duration::from_secs(1));
    group.throughput(Throughput::Elements(101));
    group.bench_function("scan_101_real_manifests", |benchmark| {
        benchmark.iter(|| {
            scan_repo(black_box(temp_dir.path()), &manager, &options)
                .expect("Le scan de production doit reussir")
        })
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_production_parsers,
    bench_production_scan,
    bench_production_throughput
);
criterion_main!(benches);

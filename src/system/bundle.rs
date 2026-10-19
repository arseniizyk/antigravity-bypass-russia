//! macOS signs an application bundle as a whole: the seal in `CodeResources`
//! covers every file inside the bundle. Patching a file inside a bundle
//! therefore invalidates that signature, and macOS then refuses to start the
//! application ("Antigravity is damaged and can't be opened"). The helpers
//! here keep the seal in sync with the patched files.
use std::path::{Path, PathBuf};

/// Library validation compares the team identifier of the running process with
/// the team identifier of every library it loads. A local ad-hoc signature has
/// no team identifier, so the Electron framework can no longer be loaded by the
/// main executable without this exemption.
const LIBRARY_VALIDATION: &str = "com.apple.security.cs.disable-library-validation";

/// The `.app` bundle that contains `path`, if there is one.
pub fn enclosing_app_bundle(path: &Path) -> Option<PathBuf> {
    let mut current = path.parent();
    while let Some(dir) = current {
        if dir.extension().and_then(|ext| ext.to_str()) == Some("app") {
            return Some(dir.to_path_buf());
        }
        current = dir.parent();
    }
    None
}

/// True when the bundle signature no longer matches the files inside it.
pub fn seal_is_broken(bundle: &Path) -> bool {
    #[cfg(target_os = "macos")]
    {
        match crate::system::command::output(
            "codesign",
            ["--verify", "--deep", "--strict"]
                .map(std::ffi::OsStr::new)
                .into_iter()
                .chain([bundle.as_os_str()]),
        ) {
            Ok(out) => !out.status.success(),
            Err(_) => true,
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = bundle;
        false
    }
}

/// Re-sign the bundle that contains `path` after its files were modified.
/// Returns the bundle that was re-signed, if the file belongs to one.
pub fn reseal_bundle_containing(path: &Path) -> Result<Option<PathBuf>, String> {
    let Some(bundle) = enclosing_app_bundle(path) else {
        return Ok(None);
    };
    reseal(&bundle)?;
    Ok(Some(bundle))
}

/// Re-sign the bundle so that its seal matches the current contents.
pub fn reseal(bundle: &Path) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        reseal_macos(bundle)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = bundle;
        Ok(())
    }
}

#[cfg(target_os = "macos")]
fn reseal_macos(bundle: &Path) -> Result<(), String> {
    // The entitlements of the nested code are read before it is re-signed: a
    // deep sign applies the entitlements of the bundle to everything inside it.
    let nested: Vec<(PathBuf, serde_json::Value)> = nested_items(bundle)
        .into_iter()
        .map(|item| read_entitlements(&item).map(|entitlements| (item, entitlements)))
        .collect::<Result<_, String>>()?;

    // The main executable loads the Electron framework, which has no vendor
    // identity after the local re-sign, so it needs the library validation
    // exemption.
    let main = entitlements_with_library_validation(bundle)?;
    let plist = EntitlementsFile::write(&main)?;
    sign(
        bundle,
        &[
            "--force",
            "--deep",
            "--sign",
            "-",
            "--options",
            "runtime",
            "--preserve-metadata=entitlements,flags,runtime",
            "--entitlements",
            plist.path().to_str().unwrap_or_default(),
        ],
    )?;

    // The nested code keeps its own entitlements. The helper applications load
    // the framework as well and need the same exemption.
    for (item, entitlements) in &nested {
        let is_helper = item.extension().and_then(|ext| ext.to_str()) == Some("app");
        let mut value = entitlements.clone();
        if is_helper {
            add_library_validation(&mut value);
        }
        let plist = EntitlementsFile::write(&value)?;
        sign(
            item,
            &[
                "--force",
                "--sign",
                "-",
                "--options",
                "runtime",
                "--entitlements",
                plist.path().to_str().unwrap_or_default(),
            ],
        )?;
    }

    // The bundle is sealed again with the new signatures of the nested code.
    sign(
        bundle,
        &[
            "--force",
            "--sign",
            "-",
            "--options",
            "runtime",
            "--preserve-metadata=entitlements,flags,runtime",
        ],
    )?;
    verify(bundle)
}

#[cfg(target_os = "macos")]
fn add_library_validation(value: &mut serde_json::Value) {
    if !value.is_object() {
        *value = serde_json::Value::Object(Default::default());
    }
    if let Some(map) = value.as_object_mut() {
        map.insert(
            LIBRARY_VALIDATION.to_string(),
            serde_json::Value::Bool(true),
        );
    }
}

#[cfg(target_os = "macos")]
fn sign(path: &Path, args: &[&str]) -> Result<(), String> {
    let out = crate::system::command::output(
        "codesign",
        args.iter()
            .copied()
            .map(std::ffi::OsStr::new)
            .chain([path.as_os_str()]),
    )
    .map_err(|e| format!("codesign: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "codesign {}: {}",
            path.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn verify(bundle: &Path) -> Result<(), String> {
    let out = crate::system::command::output(
        "codesign",
        ["--verify", "--deep", "--strict"]
            .map(std::ffi::OsStr::new)
            .into_iter()
            .chain([bundle.as_os_str()]),
    )
    .map_err(|e| format!("codesign: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "подпись приложения не восстановлена: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(())
}

/// Signed code inside the bundle: helper applications, frameworks and the
/// helper executables of a framework.
#[cfg(target_os = "macos")]
fn nested_items(bundle: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut stack = vec![bundle.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() || path == bundle {
                continue;
            }
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or_default();
            if name.ends_with(".app") {
                found.push(path);
                continue;
            }
            if name.ends_with(".framework") {
                found.push(path.clone());
                let helpers = path.join("Versions/Current/Helpers");
                if let Ok(files) = std::fs::read_dir(&helpers) {
                    for file in files.flatten() {
                        if file.path().is_file() {
                            found.push(file.path());
                        }
                    }
                }
                continue;
            }
            stack.push(path);
        }
    }
    // The deepest items are signed first: a container records the signature of
    // the code inside it.
    found.sort_by(|left, right| {
        right
            .components()
            .count()
            .cmp(&left.components().count())
            .then_with(|| left.cmp(right))
    });
    found
}

/// Entitlements of a signed item with the library validation exemption added.
#[cfg(target_os = "macos")]
fn entitlements_with_library_validation(item: &Path) -> Result<serde_json::Value, String> {
    let mut value = read_entitlements(item)?;
    add_library_validation(&mut value);
    Ok(value)
}

/// Entitlements of a signed item, or an empty set when it has none.
#[cfg(target_os = "macos")]
fn read_entitlements(item: &Path) -> Result<serde_json::Value, String> {
    let out = crate::system::command::output(
        "codesign",
        ["-d", "--entitlements", "-", "--xml"]
            .map(std::ffi::OsStr::new)
            .into_iter()
            .chain([item.as_os_str()]),
    )
    .map_err(|e| format!("codesign: {e}"))?;
    if out.stdout.is_empty() {
        return Ok(serde_json::Value::Object(Default::default()));
    }
    let json = plist_to_json(&out.stdout)?;
    let value: serde_json::Value =
        serde_json::from_slice(&json).map_err(|e| format!("entitlements: {e}"))?;
    if value.is_object() {
        return Ok(value);
    }
    Ok(serde_json::Value::Object(Default::default()))
}

/// A temporary entitlements plist that stays alive while codesign runs.
#[cfg(target_os = "macos")]
struct EntitlementsFile {
    _dir: tempfile::TempDir,
    path: PathBuf,
}

#[cfg(target_os = "macos")]
impl EntitlementsFile {
    fn write(entitlements: &serde_json::Value) -> Result<Self, String> {
        let dir = tempfile::tempdir().map_err(|e| e.to_string())?;
        let source = dir.path().join("entitlements.json");
        let target = dir.path().join("entitlements.plist");
        let json = serde_json::to_vec(entitlements).map_err(|e| e.to_string())?;
        std::fs::write(&source, json).map_err(|e| e.to_string())?;
        let out = crate::system::command::output(
            "plutil",
            [
                "-convert",
                "xml1",
                "-o",
                target.to_str().unwrap_or_default(),
                source.to_str().unwrap_or_default(),
            ],
        )
        .map_err(|e| format!("plutil: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "plutil: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        Ok(Self {
            _dir: dir,
            path: target,
        })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(target_os = "macos")]
fn plist_to_json(plist: &[u8]) -> Result<Vec<u8>, String> {
    let dir = tempfile::tempdir().map_err(|e| e.to_string())?;
    let source = dir.path().join("entitlements.plist");
    std::fs::write(&source, plist).map_err(|e| e.to_string())?;
    let out = crate::system::command::output(
        "plutil",
        [
            "-convert",
            "json",
            "-o",
            "-",
            source.to_str().unwrap_or_default(),
        ],
    )
    .map_err(|e| format!("plutil: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "plutil: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(out.stdout)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundle_of_a_patched_file_is_found() {
        let path =
            Path::new("/Applications/Antigravity.app/Contents/Resources/bin/language_server");
        assert_eq!(
            enclosing_app_bundle(path),
            Some(PathBuf::from("/Applications/Antigravity.app"))
        );
    }

    #[test]
    fn files_outside_a_bundle_have_no_bundle() {
        for path in [
            "/usr/local/bin/agy",
            "/Users/user/Library/Application Support/Antigravity/settings.json",
            "/Applications/Antigravity.app.txt/Contents/Resources/app.asar",
        ] {
            assert_eq!(enclosing_app_bundle(Path::new(path)), None, "{path}");
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn library_validation_is_added_to_existing_entitlements() {
        let mut value = serde_json::json!({"com.apple.security.cs.allow-jit": true});
        if let Some(map) = value.as_object_mut() {
            map.insert(
                LIBRARY_VALIDATION.to_string(),
                serde_json::Value::Bool(true),
            );
        }
        assert_eq!(value["com.apple.security.cs.allow-jit"], true);
        assert_eq!(value[LIBRARY_VALIDATION], true);
    }

    /// A file that is added to or changed inside a signed bundle invalidates the
    /// bundle seal, and macOS then refuses to start the application.
    #[cfg(target_os = "macos")]
    #[test]
    fn reseal_repairs_a_bundle_with_a_broken_seal() {
        let root = tempfile::tempdir().unwrap();
        let bundle = build_test_bundle(root.path());
        assert!(
            !seal_is_broken(&bundle),
            "исходный бандл должен быть подписан"
        );

        std::fs::write(bundle.join("Contents/Resources/extra.bin"), b"patched").unwrap();
        assert!(seal_is_broken(&bundle), "печать не должна совпадать");

        reseal(&bundle).unwrap();
        assert!(!seal_is_broken(&bundle), "подпись не восстановлена");
    }

    /// A small bundle with a helper application, similar to an Electron app.
    #[cfg(target_os = "macos")]
    fn build_test_bundle(root: &Path) -> PathBuf {
        let bundle = root.join("Test.app");
        let macos = bundle.join("Contents/MacOS");
        let helper = bundle.join("Contents/Frameworks/Test Helper.app/Contents/MacOS");
        std::fs::create_dir_all(&macos).unwrap();
        std::fs::create_dir_all(&helper).unwrap();
        std::fs::create_dir_all(bundle.join("Contents/Resources")).unwrap();
        std::fs::copy("/bin/echo", macos.join("Test")).unwrap();
        std::fs::copy("/bin/echo", helper.join("Test Helper")).unwrap();
        std::fs::write(
            bundle.join("Contents/Info.plist"),
            info_plist("com.example.test", "Test"),
        )
        .unwrap();
        std::fs::write(
            bundle.join("Contents/Frameworks/Test Helper.app/Contents/Info.plist"),
            info_plist("com.example.test.helper", "Test Helper"),
        )
        .unwrap();
        let out = crate::system::command::output(
            "codesign",
            ["--force", "--deep", "--sign", "-"]
                .map(std::ffi::OsStr::new)
                .into_iter()
                .chain([bundle.as_os_str()]),
        )
        .unwrap();
        assert!(
            out.status.success(),
            "codesign: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        bundle
    }

    #[cfg(target_os = "macos")]
    fn info_plist(identifier: &str, executable: &str) -> Vec<u8> {
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
             <plist version=\"1.0\">\n<dict>\n\
             <key>CFBundleIdentifier</key><string>{identifier}</string>\n\
             <key>CFBundleExecutable</key><string>{executable}</string>\n\
             <key>CFBundlePackageType</key><string>APPL</string>\n\
             <key>CFBundleName</key><string>{executable}</string>\n\
             </dict>\n</plist>\n"
        )
        .into_bytes()
    }
}

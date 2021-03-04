use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};

pub fn secure_join<P1: AsRef<Path>, P2: AsRef<Path>>(
    root: &P1,
    unsafe_path: &P2,
) -> io::Result<PathBuf> {
    let mut current_path: std::collections::VecDeque<std::ffi::OsString> = unsafe_path
        .as_ref()
        .to_path_buf()
        .components()
        .map(|c| OsString::from(c.as_os_str()))
        .collect();
    let mut path = PathBuf::new();
    let mut n = 0;

    loop {
        n = n + 1;
        if n > 255 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "meet symlink loop",
            ));
        }

        if let Some(component) = &current_path.pop_front() {
            if component == "/" {
                path.clear();
            } else if component == "." {
                // do nothing
            } else if component == ".." {
                path.pop();
            } else {
                let real_path = root.as_ref().join(&path);
                match std::fs::read_link(real_path) {
                    Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                        path.push(component);
                        // Keep non-existent path components.
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::InvalidInput => {
                        path.push(component);
                        // Ignore normal path.
                    }
                    Err(err) => return Err(err),
                    Ok(symlink) => {
                        if symlink.is_absolute() {
                            path.clear();
                        } else {
                            let mut path = symlink.clone();
                            for rest_component in current_path.iter() {
                                path = path.join(rest_component);
                            }
                            current_path = path
                                .components()
                                .map(|c| OsString::from(c.as_os_str()))
                                .collect();
                        }
                    }
                }
            }
        } else {
            break;
        }
    }

    Ok(root.as_ref().join(&path))
}

#[cfg(test)]
mod tests {
    #[test]
    fn no_change() {
        assert_eq!(
            std::path::PathBuf::from("/nonexistent/a/b/c/d/e"),
            super::secure_join(&"/nonexistent/a/b/c/d/e", &"").unwrap()
        );
    }

    #[test]
    fn normal_join() {
        assert_eq!(
            std::path::PathBuf::from("/nonexistent/a/b/c/d/e"),
            super::secure_join(&"/nonexistent", &"a/b/c/d/e").unwrap()
        );
    }

    #[test]
    fn absolute_path() {
        assert_eq!(
            std::path::PathBuf::from("/nonexistent/a/b/c/d/e"),
            super::secure_join(&"/nonexistent", &"/a/b/c/d/e").unwrap()
        );
    }

    #[test]
    fn parent_dir() {
        assert_eq!(
            std::path::PathBuf::from("/nonexistent/a/c"),
            super::secure_join(&"/nonexistent", &"a/b/../c").unwrap()
        );
    }

    #[test]
    fn parent_dir_out_of_scope() {
        assert_eq!(
            std::path::PathBuf::from("/nonexistent/c"),
            super::secure_join(&"/nonexistent", &"../../c").unwrap()
        );
    }
}

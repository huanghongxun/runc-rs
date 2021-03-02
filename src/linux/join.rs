use std::io;
use std::path::{Component, Path, PathBuf};

pub fn secure_join<P1: AsRef<Path>, P2: AsRef<Path>>(
    root: &P1,
    unsafe_path: &P2,
) -> io::Result<PathBuf> {
    let mut current_path = unsafe_path.as_ref().to_path_buf();
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
        match current_path.components().next() {
            None => break,
            Some(Component::RootDir) => {
                path.clear();
            }
            Some(Component::CurDir) => continue,
            Some(Component::Normal(c)) => {
                let real_path = root.as_ref().join(&path);
                match std::fs::read_link(real_path) {
                    Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                        path.push(c);
                        // Keep non-existent path components.
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::InvalidInput => {
                        path.push(c);
                        // Ignore normal path.
                    }
                    Err(err) => return Err(err),
                    Ok(symlink) => {
                        if symlink.is_absolute() {
                            path.clear();
                        } else {
                            current_path = symlink.join(current_path);
                        }
                    }
                }
            }
            Some(Component::ParentDir) => {
                path.pop();
            }
            Some(Component::Prefix(_)) => unreachable!(),
        }
    }

    Ok(path)
}

#[cfg(test)]
mod tests {
    #[test]
    fn no_change() {
        assert_eq!(
            std::path::PathBuf::from("/nonexistent/a/b/c/d/e"),
            Ok(super::secure_join(&"/nonexistent/a/b/c/d/e", &""))
        );
    }

    #[test]
    fn normal_join() {
        assert_eq!(
            std::path::PathBuf::from("/nonexistent/a/b/c/d/e"),
            Ok(super::secure_join(&"/nonexistent", &"a/b/c/d/e"))
        );
    }

    #[test]
    fn absolute_path() {
        assert_eq!(
            std::path::PathBuf::from("/nonexistent/a/b/c/d/e"),
            Ok(super::secure_join(&"/nonexistent", &"/a/b/c/d/e"))
        );
    }

    #[test]
    fn parent_dir() {
        assert_eq!(
            std::path::PathBuf::from("/nonexistent/a/c"),
            Ok(super::secure_join(&"/nonexistent", &"a/b/../c"))
        );
    }

    #[test]
    fn parent_dir_out_of_scope() {
        assert_eq!(
            std::path::PathBuf::from("/nonexistent/c"),
            Ok(super::secure_join(&"/nonexistent", &"../../c"))
        );
    }
}

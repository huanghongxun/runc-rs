pub fn format_mount_label(source: &str, mount_label: &str) -> String {
    if mount_label != "" {
        match source {
            "" => format!("context={}", mount_label),
            _ => format!("{},context={}", source, mount_label),
        }
    } else {
        String::from(source)
    }
}

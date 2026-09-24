package evidence

// Windows does not expose directory fsync through os.File. File sync and the
// cooperative lock/readback do not guarantee durability across power loss.
func syncDirectory(string) error { return nil }

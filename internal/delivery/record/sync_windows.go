package record

// Windows does not expose directory fsync through os.File. File.Sync plus the
// cooperative lock and validation protect committed history; power-loss
// durability is filesystem dependent, not a guarantee of os.Rename.
func syncDirectory(string) error { return nil }

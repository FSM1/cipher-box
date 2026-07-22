// Appex entry point: FSKit discovers the FSUnaryFileSystem via the
// UnaryFileSystemExtension conformance; the FS itself lives in ObjC
// (Gate5FS.h via the bridging header).
import ExtensionFoundation
import FSKit

@main
struct Gate5Extension: UnaryFileSystemExtension {
    var fileSystem: Gate5FS { Gate5FS.shared }
}

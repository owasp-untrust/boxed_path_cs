using System;
using System.IO;
using Owasp.Untrust.BoxedPath.Internal;

namespace Owasp.Untrust.BoxedPath.IO;

/// <summary>
/// Represents a directory, securely wrapping System.IO.DirectoryInfo.
/// Does NOT inherit from DirectoryInfo to prevent path leakage.
/// </summary>
public class BoxedDirectoryInfo : BoxedFileSystemInfo
{
    // Constructor uses the base constructor and a cast to initialize InnerInfo
    public BoxedDirectoryInfo(BoxedPath path)
        // CRITICAL: Call ValidateAndExpose() to construct the internal DirectoryInfo, 
        // then pass both the secure path and the DirectoryInfo to the base constructor.
        : base(path, new DirectoryInfo(path.ValidateAndExpose()))
    {
    }

    internal BoxedDirectoryInfo(DirectoryInfo di, BoxedPath path)
        // CRITICAL: Call ValidateAndExpose() to construct the internal DirectoryInfo, 
        // then pass both the secure path and the DirectoryInfo to the base constructor.
        : base(path, di)
    {
    }

    // Methods specific to directories

    // Secure Operation: Ensures returned file results are wrapped
    public BoxedFileInfo[] GetFiles()
    {
        var directoryInfo = (DirectoryInfo)InnerInfo;
        var files = directoryInfo.GetFiles();
        var sandbox = BoxedPath.Sandbox; 
        
        return Array.ConvertAll(files, fileInfo => 
            new BoxedFileInfo(new BoxedAbsolute(sandbox, fileInfo.FullName))
        );
    }
    
    // Secure Operation: Ensures returned directory results are wrapped
    public BoxedDirectoryInfo[] GetDirectories()
    {
        var directoryInfo = (DirectoryInfo)InnerInfo;
        var directories = directoryInfo.GetDirectories();
        var sandbox = BoxedPath.Sandbox;
        
        return Array.ConvertAll(directories, dirInfo => 
            new BoxedDirectoryInfo(new BoxedAbsolute(sandbox, dirInfo.FullName))
        );
    }

    public void Delete(bool recursive = false)
    {
        ((DirectoryInfo)InnerInfo).Delete(recursive);
    }
}

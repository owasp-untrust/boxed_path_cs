using System;
using System.IO;
using Owasp.Untrust.BoxedPath.Internal;

namespace Owasp.Untrust.BoxedPath.IO;

public static class BoxedDirectory
{
    // All methods now use the validated path from GetUnsecuredPath
    public static bool Exists(BoxedPath path) => Directory.Exists(path.ValidateAndExpose());
    public static BoxedDirectoryInfo CreateDirectory(BoxedPath path)
    {
       DirectoryInfo di = Directory.CreateDirectory(path.ValidateAndExpose());
       return new BoxedDirectoryInfo(di, path);
    }

    public static void Delete(BoxedPath path, bool recursive = false) => Directory.Delete(path.ValidateAndExpose(), recursive);

    // IMPORTANT: When returning path results, they must be converted back to BoxedPath objects.
    public static BoxedPath[] GetDirectories(BoxedPath path)
    {
        string[] directoryStrings = Directory.GetDirectories(path.ValidateAndExpose());
        
        // Re-wrap and re-validate every result using the current path's Sandbox.
        var sandbox = path.Sandbox;
        return Array.ConvertAll(directoryStrings, dirString => new BoxedAbsolute(sandbox, dirString));
    }
}

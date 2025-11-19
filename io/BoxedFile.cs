using System.IO;

namespace Owasp.Untrust.BoxedPath.IO;

public static class BoxedFile
{
    // All methods now use the validated path from GetUnsecuredPath
    public static bool Exists(BoxedPath path) => File.Exists(path.ValidateAndExpose());
    public static void Delete(BoxedPath path) => File.Delete(path.ValidateAndExpose());
    public static void Copy(BoxedPath sourceFileName, BoxedPath destFileName, bool overwrite = false) => 
        File.Copy(sourceFileName.ValidateAndExpose(), destFileName.ValidateAndExpose(), overwrite);
    public static string ReadAllText(BoxedPath path) => File.ReadAllText(path.ValidateAndExpose());
    public static void WriteAllText(BoxedPath path, string contents) => File.WriteAllText(path.ValidateAndExpose(), contents);
    public static FileStream OpenRead(BoxedPath path) => File.OpenRead(path.ValidateAndExpose());
}

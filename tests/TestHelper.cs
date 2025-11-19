using System.Security;
using System.Runtime.InteropServices;
using Xunit.Sdk;
using System.IO;

namespace Owasp.Untrust.BoxedPath.Tests;

public static class TestHelper
{
    // Win32 Error Codes that indicate a permissions issue requiring Admin/Developer Mode
    private const int ERROR_PRIVILEGE_NOT_HELD = 1314; //-2147023582; // A required privilege is not held by the client
    private const int ERROR_ACCESS_DENIED = 5;         // Access is denied

    public static bool IsWindows => RuntimeInformation.IsOSPlatform(OSPlatform.Windows);
    
    // Creates a symbolic link (directory or file)
    public static void CreateLink(string symlinkPath, string targetPath, bool isDirectory)
    {
        try
        {
            if (isDirectory)
            {
                Directory.CreateSymbolicLink(symlinkPath, targetPath);
            }
            else
            {
                File.CreateSymbolicLink(symlinkPath, targetPath);
            }
        }
        // FIX: Using the static factory method SkipException.ForSkip(string message) 
        // for better semantics and compatibility in xUnit.
        catch (IOException ex) when (IsWindows && ((uint)ex.HResult & 0xFFFF) == ERROR_PRIVILEGE_NOT_HELD)
        {
            // Explicitly handle the "Privilege Not Held" Windows error
            throw SkipException.ForSkip(
                $"Skipping symlink test: Failed to create symlink at {symlinkPath}. Requires elevated permissions (Admin) or Developer Mode on Windows. HResult: {ex.HResult}"
            );
        }
        catch (UnauthorizedAccessException ex)
        {
            // Handle general UnauthorizedAccessException, which often occurs on Windows without Admin rights
            if (IsWindows)
            {
                throw SkipException.ForSkip(
                    $"Skipping symlink test: Failed to create symlink at {symlinkPath}. Requires elevated permissions (Admin) or Developer Mode on Windows. Exception: {ex.Message}"
                );
            }
            // Re-throw for other OSes if it's a true security error
            throw new XunitException($"Unauthorized access error during symlink creation: {ex.Message}", ex);
        }
        catch (Exception ex)
        {
            // Fail fast for all other unexpected errors during link creation.
            throw new XunitException($"Unexpected error during symlink creation at {symlinkPath}: {ex.Message}", ex);
        }
    }

    public static void Cleanup(string root)
    {
        if (Directory.Exists(root))
        {
            // Use try-catch for robustness in cleanup, as sometimes files are locked immediately after test runs.
            try
            {
                Directory.Delete(root, true);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Warning: Failed to cleanup directory {root}: {ex.Message}");
            }
        }
    }
}

using Owasp.Untrust.BoxedPath;
using System.Security;
using Xunit;

namespace Owasp.Untrust.BoxedPath.Tests.Functional;

public class SandboxFunctionalTests : IDisposable
{
    private readonly string _sandboxRoot;
    private readonly PathSandbox _sandbox;
    
    // Use the current temp directory as the sandbox root for real-world path validation
    public SandboxFunctionalTests()
    {
        // 1. Create a dynamic, temporary, absolute root path
        _sandboxRoot = Path.GetFullPath(Path.Combine(Path.GetTempPath(), $"FunctionalSandboxRoot_{Guid.NewGuid()}"));
        Directory.CreateDirectory(_sandboxRoot);
        
        // 2. Initialize the sandbox
        _sandbox = PathSandbox.BoxRoot(_sandboxRoot);
    }

    public void Dispose()
    {
        TestHelper.Cleanup(_sandboxRoot);
    }

    [Fact]
    public void BoxRoot_Initialization_ShouldNormalizePath()
    {
        // ARRANGE: Use a path that needs normalization (e.g., ends with separator)
        string nonNormalizedRoot = _sandboxRoot.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        
        // ACT
        PathSandbox sandbox = PathSandbox.BoxRoot(nonNormalizedRoot);
        
        // ASSERT
        // Ensure the internal path is absolute and normalized (without trailing separator, except for drive roots)
        string expectedRoot = Path.GetFullPath(_sandboxRoot).TrimEnd(Path.DirectorySeparatorChar);
        string sandboxRoot = sandbox.GetRoot().ToUncheckedAndUnsecuredString();
        sandboxRoot = sandboxRoot.TrimEnd(Path.DirectorySeparatorChar);
        Assert.Equal(expectedRoot, sandboxRoot);
    }

    [Fact]
    public void Resolve_RelativePath_ShouldBeAbsoluteAndInsideRoot()
    {
        // ARRANGE
        string relativePath = "subdir/file.txt";
        string expectedPath = Path.GetFullPath(Path.Combine(_sandboxRoot, relativePath));

        // ACT
        BoxedPath boxedPath = BoxedPath.Of(_sandbox, relativePath);

        // ASSERT
        Assert.Equal(expectedPath, boxedPath.ValidateAndExpose());
    }

    [Fact]
    public void Resolve_PathTraversal_ShouldFailSecurityCheck()
    {
        // ARRANGE: Attempting to resolve a path that escapes the root
        string maliciousPath = "../outside.txt";

        // ACT & ASSERT
        BoxedPath boxedPath = BoxedPath.Of(_sandbox, maliciousPath);
        Assert.Throws<SecurityException>(() => boxedPath.ValidateAndExpose());
    }

    [Fact]
    public void Of_AbsolutePath_OutsideSandbox_ShouldThrowSecurityException()
    {
        // ARRANGE: Create an absolute path known to be outside the sandbox root
        // This simulates the check done by the 'of' factory method on ingress.
        
        // Note: We use the system's temporary directory to guarantee it's outside.
        string pathOutsideSandbox = Path.GetTempPath(); 
        
        // The BoxedPath.Of factory method we mocked up doesn't fully implement
        // BoxedAbsolute/BoxedRelative creation logic, but this test targets the
        // general 'of' concept where an absolute path is checked on creation (ingress).
        
        // For testing the current simplified C# mock:
        // We ensure the underlying ValidateAndExpose catches the ingress/absolute path error.
        
        // Create a BoxedPath using an absolute path outside the root.
        // ACT & ASSERT: Initial lexical check should fail
        Assert.Throws<SecurityException>(() => BoxedPath.Of(_sandbox, pathOutsideSandbox));
    }
}

using Owasp.Untrust.BoxedPath;
using System.Security;
using Xunit;

namespace Owasp.Untrust.BoxedPath.Tests.Functional;

public class FunctionalTests : IDisposable
{
    private readonly string _sandboxRoot;
    private readonly PathSandbox _sandbox;

    public FunctionalTests()
    {
        _sandboxRoot = Path.GetFullPath(Path.Combine(Path.GetTempPath(), $"FunctionalTestRoot_{Guid.NewGuid()}"));
        Directory.CreateDirectory(_sandboxRoot);
        _sandbox = PathSandbox.BoxRoot(_sandboxRoot);
    }

    // Runs after every test
    public void Dispose()
    {
        TestHelper.Cleanup(_sandboxRoot);
    }

    [Fact]
    public void AbsolutePath_ShouldBeNormalizedAndPassValidation()
    {
        // ARRANGE
        string normalizedPath = Path.GetFullPath(Path.Combine(_sandboxRoot, "sub/dir/../file.txt"));
        
        // We create the path using the absolute path (BoxedAbsolute validation applies)
        BoxedPath boxedPath = BoxedPath.Of(_sandbox, normalizedPath);

        // ACT
        string exposedPath = boxedPath.ValidateAndExpose();

        // ASSERT
        // Ensure the returned path is normalized and matches the expectation
        Assert.Equal(normalizedPath, exposedPath);
    }

    [Fact]
    public void RelativePath_ShouldResolveCorrectlyOnEgress()
    {
        // ARRANGE
        string relativePath = "data/test.log";
        string expectedPath = Path.GetFullPath(Path.Combine(_sandboxRoot, relativePath));

        BoxedPath boxedPath = BoxedPath.Of(_sandbox, relativePath);

        // ACT
        string exposedPath = boxedPath.ValidateAndExpose();

        // ASSERT
        Assert.Equal(expectedPath, exposedPath);
    }

    [Theory]
    [InlineData("..\\..\\malicious.exe")]
    [InlineData("../../etc/passwd")]
    [InlineData("safe\\..\\..\\..\\malicious.exe")]
    public void LexicalTraversal_ShouldFail_WhenEscapingRoot(string relativePath)
    {
        // ARRANGE
        BoxedPath boxedPath = BoxedPath.Of(_sandbox, relativePath);

        // ACT & ASSERT
        // The GetFullPath combined with the SandboxRootAbsolutePath should fail the initial StartsWith check
        Assert.Throws<SecurityException>(() => boxedPath.ValidateAndExpose());
    }

    [Fact]
    public void LexicalTraversal_ShouldSucceed_WhenUsingDotDotInsideRoot()
    {
        // ARRANGE: data/test/../file.txt
        string relativePath = "data/test/../file.txt";
        Directory.CreateDirectory(Path.Combine(_sandboxRoot, "data", "test"));
        
        string expectedPath = Path.GetFullPath(Path.Combine(_sandboxRoot, "data", "file.txt"));
        BoxedPath boxedPath = BoxedPath.Of(_sandbox, relativePath);

        // ACT
        string exposedPath = boxedPath.ValidateAndExpose();

        // ASSERT
        Assert.Equal(expectedPath, exposedPath);
    }
}

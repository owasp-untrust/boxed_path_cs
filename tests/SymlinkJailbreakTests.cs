using Owasp.Untrust.BoxedPath;
using System.Security;
using Xunit;

namespace Owasp.Untrust.BoxedPath.Tests.Security;

// Note: These tests require the test runner to have permissions to create symlinks (often admin rights on Windows)
public class SymlinkJailbreakTests : IDisposable
{
    private readonly string _sandboxRoot;
    private readonly PathSandbox _sandbox;
    private readonly string _outsideRoot;

    public SymlinkJailbreakTests()
    {
        // 1. Set up the sandbox environment
        _sandboxRoot = Path.Combine(Path.GetTempPath(), $"SecureTestRoot_{Guid.NewGuid()}");
        Directory.CreateDirectory(_sandboxRoot);
        
        // 2. Set up a path outside the sandbox
        _outsideRoot = Path.Combine(Path.GetTempPath(), "OutsideJail");
        Directory.CreateDirectory(_outsideRoot);
        File.WriteAllText(Path.Combine(_outsideRoot, "secret.txt"), "Secret Data");
        
        // 3. Create a subdirectory and file inside the sandbox
        Directory.CreateDirectory(Path.Combine(_sandboxRoot, "data"));
        File.WriteAllText(Path.Combine(_sandboxRoot, "data", "safe.txt"), "Safe Data");

        _sandbox = PathSandbox.BoxRoot(_sandboxRoot);
    }

    // Runs after every test
    public void Dispose()
    {
        TestHelper.Cleanup(_sandboxRoot);
        TestHelper.Cleanup(_outsideRoot);
    }

    [Fact]
    public void LinkFollow_ShouldFail_WhenSymlinkPointsOutsideSandbox()
    {
        // ARRANGE
        string outsideFile = Path.Combine(_outsideRoot, "secret.txt");
        string maliciousLink = Path.Combine(_sandboxRoot, "evil_link");
        
        // Create a symlink inside the sandbox pointing to a file outside
        TestHelper.CreateLink(maliciousLink, outsideFile, isDirectory: false);
        
        // Path to validate: 'evil_link/safe.txt' (though the link should resolve to secret.txt)
        BoxedPath boxedPath = BoxedPath.Of(_sandbox, "evil_link");

        // ACT & ASSERT
        // Validation must fail when the link is followed and points outside the root
        Assert.Throws<SecurityException>(() => boxedPath.ValidateAndExpose());
    }

    [Fact]
    public void LinkFollow_ShouldFail_WhenNestedRelativeSymlinkPointsOutside()
    {
        // ARRANGE: C:\Sandbox\LinkA -> C:\Sandbox\Dir -> C:\Sandbox\Dir\LinkB -> ..\..\OutsideRoot
        
        // 1. Create intermediary safe directory
        string safeDir = Path.Combine(_sandboxRoot, "safe_dir");
        Directory.CreateDirectory(safeDir);

        // 2. Link B (inside safe_dir) points to the outside root using '..' traversal
        string outsideTarget = Path.GetFullPath(Path.Combine(_sandboxRoot, "..", "OutsideJail")); // Should resolve to the root temp dir, then OutsideJail
        
        // On Unix, use relative link from 'safe_dir' to 'OutsideJail'
        // On Windows, target might need adjustment depending on exact folder depth
        string relativeJailbreakTarget = Path.Combine("..", "..", Path.GetFileName(_outsideRoot)); 
        
        string linkB_Path = Path.Combine(safeDir, "link_b");
        TestHelper.CreateLink(linkB_Path, relativeJailbreakTarget, isDirectory: true);

        // 3. Link A (in root) points to link B
        string linkA_Path = Path.Combine(_sandboxRoot, "link_a");
        TestHelper.CreateLink(linkA_Path, linkB_Path, isDirectory: true);
        
        // Path to validate: 'link_a/secret.txt'. Traversal must fail when link B resolves.
        BoxedPath boxedPath = BoxedPath.Of(_sandbox, "link_a/secret.txt");

        // ACT & ASSERT
        Assert.Throws<SecurityException>(() => boxedPath.ValidateAndExpose());
    }

    [Fact]
    public void LinkFollow_ShouldSucceed_WhenSymlinkStaysInsideSandbox()
    {
        // ARRANGE: C:\Sandbox\Link -> C:\Sandbox\data\safe.txt
        string safeTarget = Path.Combine(_sandboxRoot, "data", "safe.txt");
        string safeLink = Path.Combine(_sandboxRoot, "safe_link");
        
        TestHelper.CreateLink(safeLink, safeTarget, isDirectory: false);
        
        BoxedPath boxedPath = BoxedPath.Of(_sandbox, "safe_link");

        // ACT
        string resolvedPath = boxedPath.ValidateAndExpose();

        // ASSERT
        Assert.Equal(safeTarget, resolvedPath);
    }
    
    [Fact]
    public void LinkFollow_ShouldFail_WhenExceedingMaxLinkFollows()
    {
        // ARRANGE: Create a cycle Link1 -> Link2 -> Link1 (MaxFollows = 5)
        var limitedSandbox = PathSandbox.BoxRoot(_sandboxRoot, maxLinkFollows: 5);
        
        string link1 = Path.Combine(_sandboxRoot, "link1");
        string link2 = Path.Combine(_sandboxRoot, "link2");
        
        TestHelper.CreateLink(link1, link2, isDirectory: true);
        TestHelper.CreateLink(link2, link1, isDirectory: true);

        // Path to validate: Start at link1
        BoxedPath boxedPath = BoxedPath.Of(limitedSandbox, "link1/data/safe.txt");

        // ACT & ASSERT
        // Traversal should fail after the 6th link follow (i.e., when remainingLinkFollows < 0)
        SecurityException ex = Assert.Throws<SecurityException>(() => boxedPath.ValidateAndExpose());
        Assert.Contains("Symlink depth limit exceeded", ex.Message);
    }

    [Fact]
    public void LinkFollow_ShouldSucceed_WhenMaxLinkFollowsIsSufficient()
    {
        // ARRANGE: Create a chain Link1 -> Link2 -> Link3 -> Link4 -> safe.txt (4 links)
        var limitedSandbox = PathSandbox.BoxRoot(_sandboxRoot, maxLinkFollows: 5);
        
        string targetFile = Path.Combine(_sandboxRoot, "data", "safe.txt");
        string link4 = Path.Combine(_sandboxRoot, "link4");
        string link3 = Path.Combine(_sandboxRoot, "link3");
        string link2 = Path.Combine(_sandboxRoot, "link2");
        string link1 = Path.Combine(_sandboxRoot, "link1");
        
        TestHelper.CreateLink(link4, targetFile, isDirectory: false);
        TestHelper.CreateLink(link3, link4, isDirectory: false);
        TestHelper.CreateLink(link2, link3, isDirectory: false);
        TestHelper.CreateLink(link1, link2, isDirectory: false);
        
        BoxedPath boxedPath = BoxedPath.Of(limitedSandbox, "link1");

        // ACT
        string resolvedPath = boxedPath.ValidateAndExpose();

        // ASSERT
        Assert.Equal(targetFile, resolvedPath);
    }
}

using Microsoft.AspNetCore.Identity;

namespace Clean.Architecture.Core.RoleAggregate;
public class Role : IdentityRole<int>
{
  public string Description { get; set; } = default!;
}

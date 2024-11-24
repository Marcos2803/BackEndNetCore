using fourfit.sistema_gestao.Context;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace fourfit.sistema_gestao.Factory
{
    public class DataFactory : IDesignTimeDbContextFactory<DataContext>
    {
        public DataContext CreateDbContext(string[] args)
        {
            var connectionstring = "Data Source=localhost,1401;Initial Catalog=DbCtFourFit;User ID=sa;Password=@MLab12366;Trust Server Certificate=True";
            var optionBulder =  new DbContextOptionsBuilder<DataContext>();
            optionBulder.UseSqlServer(connectionstring);
            return new DataContext(optionBulder.Options);
        }
    }
}

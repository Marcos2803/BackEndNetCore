using fourfit.sistema_gestao.Context;
using fourfit.sistema_gestao.Domain.Entities.Store.Venda;
using fourfit.sistema_gestao.Domain.Interfaces;
using fourfit.sistema_gestao.Repositories.Repository.Base;
using Microsoft.EntityFrameworkCore;

namespace fourfit.sistema_gestao.Repositories.Repository.Store
{
    public class VendasRepository : BaseRepository<Vendas>, IVendasServices
    {
        private readonly DataContext _dataContext;

        public VendasRepository(DataContext dataContext) : base(dataContext)
        {
            _dataContext = dataContext;
        }

        public async Task<IEnumerable<Vendas>> ObterVendasExistentes()

        {

            var resultado = await _dataContext.Set<Vendas>()
                .Include(x => x.User)
                .Include(x => x.VendaItens)
                .Include(x => x.Pagamentos)
                .ToListAsync();

            if (resultado != null)
            {
                return resultado;
            }

            return null;
        }

        public async Task<Vendas> ObterVendasPorId(int Id)
        {
            var resultado = await _dataContext.Set<Vendas>()
                .Include(x => x.User).Where(x => x.Id == Id)
                .Include(x => x.VendaItens).Where(x => x.Id == Id)
                .Include(x => x.Pagamentos).Where(x => x.Id == Id)
                .FirstOrDefaultAsync();


            if (resultado != null)
            {
                return resultado;
            }
            return null;

        }

       

    

    }
}

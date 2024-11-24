using fourfit.sistema_gestao.Context;
using fourfit.sistema_gestao.Domain.Entities.Financas;
using fourfit.sistema_gestao.Domain.Entities.Store.ControleEstoque;
using fourfit.sistema_gestao.Domain.Interfaces;
using fourfit.sistema_gestao.Repositories.Repository.Base;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace fourfit.sistema_gestao.Repositories.Repository.Store
{
    public class EstoqueRepository : BaseRepository<Estoque>, IEstoqueServices
    {
        private readonly DataContext _dataContext;
        public EstoqueRepository(DataContext dataContext) : base(dataContext)
        {
            _dataContext = dataContext;
        }
        public async Task<IEnumerable<Estoque>> ObterEstoqueExistentes()

        {
            throw new NotImplementedException();
        }

        public async Task<Estoque> ObterEstoquePorId(int Id)
        {

            return await _dataContext.Set<Estoque>().FindAsync(Id);
        }
    }
}

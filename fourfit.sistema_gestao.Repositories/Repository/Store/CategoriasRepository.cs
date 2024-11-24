using fourfit.sistema_gestao.Context;
using fourfit.sistema_gestao.Domain.Entities.Alunos;
using fourfit.sistema_gestao.Domain.Entities.Financas;
using fourfit.sistema_gestao.Domain.Entities.Store.ControleEstoque;
using fourfit.sistema_gestao.Domain.Interfaces;
using fourfit.sistema_gestao.Repositories.Repository.Base;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace fourfit.sistema_gestao.Repositories.Repository.Store
{
    public class CategoriasRepository : BaseRepository<Categorias>, ICategoriasServices
    {
        private readonly DataContext _dataContext;

        public CategoriasRepository(DataContext dataContext) : base(dataContext)
        {
            _dataContext = dataContext;
        }
        public async Task<IEnumerable<Categorias>> ObterCategoriasExistentes()

        {
            throw new NotImplementedException();
        }

        public async Task<Categorias> ObterCategoriasPorId(int Id)
        {

            return await _dataContext.Set<Categorias>().FindAsync(Id);
        }
    }
}

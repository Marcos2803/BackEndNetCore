using fourfit.sistema_gestao.Context;
using fourfit.sistema_gestao.Domain.Interfaces.Base;
using Microsoft.EntityFrameworkCore;

namespace fourfit.sistema_gestao.Repositories.Repository.Base
{
    public class BaseRepository<TEntity> : IDisposable, IBaseServices<TEntity> where TEntity : class
    {
        private readonly DataContext _dataContext;

        public BaseRepository(DataContext dataContext)
        {
            _dataContext = dataContext;
        }


        public async Task Cadastro(TEntity entity)
        {
            await _dataContext.Set<TEntity>().AddAsync(entity);
            await Salvar();
        }
        public async Task Atualizar(TEntity entity)
        {
            _dataContext.Set<TEntity>().Update(entity);
            await Salvar();
        }
        public async Task Deletar(int Id)
        {
            var entity = await ObterPorId(Id);
            if (entity != null)
                _dataContext.Set<TEntity>().Remove(entity);
            await Salvar();
        }

        public async Task<TEntity> ObterPorId(int Id)
        {
            return await _dataContext.Set<TEntity>().FindAsync(Id);
        }

        public async Task<TEntity> ObterPorNome(string nome)
        {
            return await _dataContext.Set<TEntity>().FindAsync(nome);
        }

        public async Task<IEnumerable<TEntity>> ObterTodos()
        {
            return await _dataContext.Set<TEntity>().AsTracking().ToListAsync();
        }

        public void Dispose()
        {
            _dataContext.Dispose();
        }

        public async Task Salvar()
        {
            await _dataContext.SaveChangesAsync();
        }


    }
}

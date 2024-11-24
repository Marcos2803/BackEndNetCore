using fourfit.sistema_gestao.Context;
using fourfit.sistema_gestao.Domain.Entities.Alunos;
using fourfit.sistema_gestao.Domain.Enumerables;
using fourfit.sistema_gestao.Domain.Interfaces;
using fourfit.sistema_gestao.Repositories.Repository.Base;
using Microsoft.EntityFrameworkCore;

namespace fourfit.sistema_gestao.Repositories.Repository.Alunos
{
    public class AlunosRepository : BaseRepository<EntidadeAlunos>, IAlunosServices
    {
        private readonly DataContext _dataContext;

        public AlunosRepository(DataContext dataContext) : base(dataContext)
        {
            _dataContext = dataContext;
        }
        public async Task<IEnumerable<EntidadeAlunos>> ObterAlunosExistentes()

        {

            var resultado = await _dataContext.Set<EntidadeAlunos>()
                .Include(x => x.User)
                .ToListAsync();

            if (resultado != null)
            {
                return resultado;
            }

            return null;
        }

        public async Task<IEnumerable<EntidadeAlunos>> ObterAlunosPorCpf(string cpf)
        {
            return await _dataContext.Set<EntidadeAlunos>()
                .Where(x => x.UserId == cpf)
                .AsNoTracking()
                .ToListAsync();
        }

        public async Task<EntidadeAlunos> ObterAlunoPorUserId(string userId)
        {
            var result = await _dataContext.Set<EntidadeAlunos>()
                .Include(x => x.User)
                .Where(x => x.UserId == userId)
                .FirstOrDefaultAsync();

            if (result != null)
            {
                return result;
            }
            return null;
        }

        public async Task<EntidadeAlunos> ObterAlunosUsuariosPorId(int Id)
        {
            var resultado = await _dataContext.Set<EntidadeAlunos>()
                .Include(x => x.User).Where(x => x.Id == Id).FirstOrDefaultAsync();


            if (resultado != null)
            {
                return resultado;
            }
            return null;

        }

        public async Task<IEnumerable<EntidadeAlunos>> ObterAlunosPendentes()

        {

            var resultado = await _dataContext.Set<EntidadeAlunos>()
                .Include(x => x.User)
                .Where(x => x.StatusAlunos == StatusAlunosEnum.Pendente)
                .ToListAsync();

            if (resultado != null)
            {
                return resultado;
            }

            return null;
        }
        public async Task<IEnumerable<EntidadeAlunos>> ObterAlunosAtivos()

        {

            var resultado = await _dataContext.Set<EntidadeAlunos>()
                .Include(x => x.User)
                .Where(x => x.StatusAlunos == StatusAlunosEnum.Ativo)
                .ToListAsync();

            if (resultado != null)
            {
                return resultado;
            }

            return null;
        }
        //public async Task<bool> ObterAlunoPorUserId(string userId)
        //{
        //    return await _dataContext.Set<EntidadeAlunos>().AnyAsync(a => a.UserId == userId);
        //}



        //public async Task Remover(EntidadeAlunos aluno)
        //{
        //    var alunoExistente = await _dataContext.Alunos.FindAsync(aluno.Id);

        //    if (alunoExistente != null)
        //    {
        //        _dataContext.Alunos.Remove(alunoExistente);
        //        await _dataContext.SaveChangesAsync();
        //    }
        //    else
        //    {
        //        throw new Exception("Aluno não encontrado");
        //    }
        //}

    }
}

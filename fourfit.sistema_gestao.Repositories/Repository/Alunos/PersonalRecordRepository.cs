using fourfit.sistema_gestao.Context;
using fourfit.sistema_gestao.Domain.Entities.Alunos;
using fourfit.sistema_gestao.Domain.Interfaces;
using fourfit.sistema_gestao.Repositories.Repository.Base;
using Microsoft.EntityFrameworkCore;

namespace fourfit.sistema_gestao.Repositories.Repository.Alunos
{
    public class PersonalRecordRepository : BaseRepository<PersonalRecord>, IPersonalRecordServices
    {
        private readonly DataContext _dataContext;

        public PersonalRecordRepository(DataContext dataContext) : base(dataContext)
        {
            _dataContext = dataContext;
        }

        public async Task<IEnumerable<PersonalRecord>> ObterPersonalRecordExistentes()

        {

            var resultado = await _dataContext.Set<PersonalRecord>()
                .Include(x => x.Alunos)
                .ToListAsync();

            if (resultado != null)
            {
                return resultado;
            }

            return null;
        }

        public async Task<PersonalRecord> ObterPersonalRecordPorId(int Id)
        {
            var resultado = await _dataContext.Set<PersonalRecord>()
                .Include(x => x.Alunos).Where(x => x.Id == Id).FirstOrDefaultAsync();


            if (resultado != null)
            {
                return resultado;
            }
            return null;

        }
    }
}

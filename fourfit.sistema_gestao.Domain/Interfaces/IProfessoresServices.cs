using fourfit.sistema_gestao.Domain.Entities.Alunos;
using fourfit.sistema_gestao.Domain.Entities.Profission;
using fourfit.sistema_gestao.Domain.Interfaces.Base;

namespace fourfit.sistema_gestao.Domain.Interfaces
{
    public interface IProfessoresServices : IBaseServices<EntidadeProfessores>
    {
        Task<IEnumerable<EntidadeProfessores>> ObterProfessoresExistentes();

        Task<EntidadeProfessores> ObterProfessoresUsuariosPorId(int Id);

        Task<EntidadeProfessores> ObterProfessoresUserId(string UserId);

        //Task<EntidadeProfessores> ObterProfessoresPorId(int Id);

        Task<EntidadeProfessores> ObterProfessoresPorId(int ProfessoresId);


    }
}

using fourfit.sistema_gestao.Domain.Entities.Alunos;
using fourfit.sistema_gestao.Domain.Interfaces.Base;


namespace fourfit.sistema_gestao.Domain.Interfaces
{
    public interface IAlunosServices:IBaseServices<EntidadeAlunos>
    {
        Task<IEnumerable<EntidadeAlunos>> ObterAlunosPorCpf(string cpf);

        Task<EntidadeAlunos> ObterAlunoPorUserId(string UserId);

        Task<IEnumerable<EntidadeAlunos>> ObterAlunosExistentes();

        Task<EntidadeAlunos> ObterAlunosUsuariosPorId(int Id);

        Task<IEnumerable<EntidadeAlunos>> ObterAlunosPendentes();

        Task<IEnumerable<EntidadeAlunos>> ObterAlunosAtivos();

    }


}

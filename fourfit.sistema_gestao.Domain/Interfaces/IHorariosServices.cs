using fourfit.sistema_gestao.Domain.Entities.Alunos;
using fourfit.sistema_gestao.Domain.Interfaces.Base;


namespace fourfit.sistema_gestao.Domain.Interfaces
{
    public interface IHorariosServices : IBaseServices<Horarios>
    {
       

        Task<IEnumerable<Horarios>> ObterHorariosExistentes();

        //Task<IEnumerable<Horarios>> ObterHorariosPorId(int Id);

        Task<Horarios> ObterHorariosPorId(int Id);


    }
    
}

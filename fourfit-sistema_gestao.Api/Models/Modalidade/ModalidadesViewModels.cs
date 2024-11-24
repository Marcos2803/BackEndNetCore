using fourfit.sistema_gestao.Domain.Entities.Alunos;
using System.Numerics;

namespace fourfit_sistema_gestao.Api.Models.Modalidade
{
    public class ModalidadesViewModels
    {
        public int Id { get; set; }
        public string Nome { get; set; }
        public string Descricao { get; set; }
        public int PlanosId { get; set; }
        public string status { get; set; }
        public string AceitaCheckin { get; set; }

    }
}

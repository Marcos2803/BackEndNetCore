using fourfit_sistema_gestao.Api.Models.EntityGenerics;

namespace fourfit_sistema_gestao.Api.Models.Professores
{
    public class ProfessoresViewModels : GenericsViewModels
    {
        public int Id { get; set; }
        public string? UserId { get; set; }
        public byte[]? Foto { get; set; }
        public string Status { get; set; }
        public int? Cref { get; set; }
        public string? Especialidade { get; set; }
        public DateTime DataCadastro { get; set; }
    }
}

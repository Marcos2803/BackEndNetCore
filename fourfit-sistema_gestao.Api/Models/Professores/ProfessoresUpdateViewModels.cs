using fourfit_sistema_gestao.Api.Models.EntityGenerics;

namespace fourfit_sistema_gestao.Api.Models.Professores
{
    public class ProfessoresUpdateViewModels : GenericsViewModels
    {
        public int Id { get; set; }
        public byte[]? Foto { get; set; }
        public string PrimeiroNome { get; set; }
        public string SobreNome { get; set; }
        public int? Cref { get; set; }
        public string Especialidade { get; set; }
        public string Email { get; set; }
    }
}

using fourfit_sistema_gestao.Api.Models.EntityGenerics;

namespace fourfit_sistema_gestao.Api.Models.Colaboradores
{
    public class ColaboradoresUpdateViewModels : GenericsViewModels
    {
        public int Id { get; set; }
        public byte[]? Foto { get; set; }
        public string PrimeiroNome { get; set; }
        public string SobreNome { get; set; }
        public string Email { get; set; }
    }
}

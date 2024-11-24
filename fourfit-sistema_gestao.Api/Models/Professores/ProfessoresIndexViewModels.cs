using fourfit_sistema_gestao.Api.Models.EntityGenerics;

namespace fourfit_sistema_gestao.Api.Models.Professores
{
    public class ProfessoresIndexViewModels : GenericsViewModels    
    { 
        public int Id { get; set; }
        public byte[] Foto { get; set; }
        public string NomeCompleto { get; set; }
        public int Cref { get; set; }
        public string Especialidade { get; set; }
        public bool Ativo { get; set; }
    }
}

using fourfit.sistema_gestao.Domain.Entities;
using fourfit_sistema_gestao.Api.Models.EntityGenerics;

namespace fourfit_sistema_gestao.Api.Models.Alunos
{
    public class AlunosIndexViewModels : GenericsViewModels
    { 
        public int Id { get; set; }
        public byte[] Foto { get; set; }
        public string NomeCompleto { get; set; }
        public bool Ativo { get; set; }
    }
}

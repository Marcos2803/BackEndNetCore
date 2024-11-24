using fourfit_sistema_gestao.Api.Models.EntityGenerics;

namespace fourfit_sistema_gestao.Api.Models.Colaboradores
{
    public class ColaboradoresIndexViewModels : GenericsViewModels
    {
        public int Id { get; set; }
        public byte[] Foto { get; set; }
        public string NomeCompleto { get; set; }
        public bool Ativo { get; set; }
    }
}

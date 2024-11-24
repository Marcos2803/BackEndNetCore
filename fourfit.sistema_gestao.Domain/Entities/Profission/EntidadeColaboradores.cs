using fourfit.sistema_gestao.Domain.Entities.Account;
using fourfit.sistema_gestao.Domain.Entities.Alunos;
using fourfit.sistema_gestao.Domain.Entities.Financas;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace fourfit.sistema_gestao.Domain.Entities.Profission
{
    public class EntidadeColaboradores : Generics
    {
        public int Id { get; set; }
        public string? UserId { get; set; }
        public User User { get; set; }
        public string Status { get; set; }
        public byte[]? Foto { get; set; }
        public DateTime DataCadastro { get; set; }

        public ICollection<TipoDespesas> TipoDespesas { get; set; }
    }
}

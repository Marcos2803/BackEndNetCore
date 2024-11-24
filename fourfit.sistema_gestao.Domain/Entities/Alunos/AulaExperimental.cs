using fourfit.sistema_gestao.Domain.Entities.Account;
using fourfit.sistema_gestao.Domain.Interfaces;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace fourfit.sistema_gestao.Domain.Entities.Alunos
{
    public class AulaExperimental
    {
        public int Id { get; set; }
        public string UserId { get; set; }
        public User User { get; set; }
        public int HorariosId { get; set; }
        public Horarios Horarios { get; set; }
        public DateTime DataHExperimental { get; set; }

    }
}

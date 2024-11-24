using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace fourfit.sistema_gestao.Domain.Entities.EmailConfig
{
    public class entidadeEmailConfiguracoes
    {
        public int Id { get; set; }
        public string? Smtp { get; set; }
        public int Port { get; set; }
        public string? EmailUser { get; set; }
    }
}

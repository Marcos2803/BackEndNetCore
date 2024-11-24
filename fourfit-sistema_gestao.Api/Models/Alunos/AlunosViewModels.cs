﻿using fourfit.sistema_gestao.Domain.Enumerables;
using fourfit_sistema_gestao.Api.Models.EntityGenerics;

namespace fourfit_sistema_gestao.Api.Models.Alunos
{
    public class AlunosViewModels : GenericsViewModels
    {
        public int Id { get; set; }
        public string? UserId { get; set; }
        public StatusAlunosEnum StatusAlunos { get; set; }
        public byte[]? Foto { get; set; }
       


    }
}
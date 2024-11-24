using fourfit.sistema_gestao.Domain.Entities.Alunos;
using fourfit.sistema_gestao.Domain.Enumerables;
using fourfit.sistema_gestao.Domain.Interfaces;
using fourfit_sistema_gestao.Api.Models.Planos;
using fourfit_sistema_gestao.Api.Validation;
using Microsoft.AspNetCore.Mvc;
using Swashbuckle.AspNetCore.Annotations;

namespace fourfit_sistema_gestao.Api.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class PlanosController : ControllerBase
    {
        private readonly IUnitOfWork _unitOfWork;

        public PlanosController(IUnitOfWork unitOfWork)
        {
            _unitOfWork = unitOfWork;
        }

        [HttpPost]
        [Route("Register")]
        //[Authorize]
        [SwaggerResponse(statusCode: 200, description: "Plano cadastrado com sucesso", Type = typeof(PlanosViewModels))]
        [SwaggerResponse(statusCode: 400, description: "Campos obrigatórios", Type = typeof(ValidarCampos))]
        [SwaggerResponse(statusCode: 500, description: "Erro internet", Type = typeof(ErrosGenericos))]
        [SwaggerResponse(statusCode: 401, description: "Não autorizado", Type = typeof(ValidarCampos))]
        [SwaggerResponse(statusCode: 404, description: "Usuário nao autenticado", Type = typeof(PlanosViewModels))]
        public async Task<IActionResult> Register(PlanosViewModels model)
        {
            try
            {
                var planos = new TipoPlano
                {
                    Id = model.Id,
                    NomePlano = model.NomePlano,
                    Descricao = model.Descricao,
                    DiaPorSemana = model.DiaPorSemana,
                    DuracaoMes = model.DuracaoMes,
                    DuracaoDia = model.DuracaoDia,
                    ValorPlano = model.ValorPlano,
                    StatusPlanos = StatusPlanosEnum.Ativo,

                };

                await _unitOfWork.TipoPlanoServices.Cadastro(planos);
                await _unitOfWork.TipoPlanoServices.Salvar();
                return Ok($"Plano cadastrados com sucesso");
            }
            catch (Exception ex)
            {

                throw new Exception(ex.Message);
            }

        }

        [HttpGet]
        [Route("Update/{id}")]
        [SwaggerResponse(200, "Informações do plano obtidas com sucesso", typeof(PlanosUpdateViewModels))]
        [SwaggerResponse(404, "Plano não encontrado")]
        public async Task<IActionResult> Update(int id)
        {
            var planos = await _unitOfWork.TipoPlanoServices.ObterPlanosPorId(id);

            if (planos == null)
            {
                return NotFound("Plano não encontrado");
            }

            var planosView = new PlanosUpdateViewModels
            {
                Id = planos.Id,
                NomePlano = planos.NomePlano,
                Descricao = planos.Descricao,
                DiaPorSemana = planos.DiaPorSemana,
                DuracaoMes = planos.DuracaoMes,
                DuracaoDia = planos.DuracaoDia,
                ValorPlano = planos.ValorPlano,
                StatusPlanos = planos.StatusPlanos,
            };

            return Ok(planosView);
        }

        [HttpPut]
        [Route("Update")]
        [SwaggerResponse(statusCode: 200, description: "Plano atualizado com sucesso", Type = typeof(PlanosUpdateViewModels))]
        [SwaggerResponse(statusCode: 400, description: "Campos obrigatórios", Type = typeof(ValidarCampos))]
        [SwaggerResponse(statusCode: 500, description: "Erro internet", Type = typeof(ErrosGenericos))]
        [SwaggerResponse(statusCode: 401, description: "Não autorizado", Type = typeof(ValidarCampos))]
        [SwaggerResponse(statusCode: 404, description: "Plano não encontrado", Type = typeof(PlanosUpdateViewModels))]
        public async Task<IActionResult> Update(PlanosUpdateViewModels model)
        {
            try
            {

                var planos = await _unitOfWork.TipoPlanoServices.ObterPorId(model.Id);
                if (planos == null)
                {
                    return NotFound("Plano não encontrado");
                }
                planos.NomePlano = model.NomePlano;
                planos.Descricao = model.Descricao;
                planos.DiaPorSemana = model.DiaPorSemana;
                planos.DuracaoMes = model.DuracaoMes;
                planos.DuracaoDia = model.DuracaoDia;
                planos.ValorPlano = model.ValorPlano;
                planos.StatusPlanos = model.StatusPlanos;

                await _unitOfWork.TipoPlanoServices.Atualizar(planos);
                await _unitOfWork.TipoPlanoServices.Salvar();

                return Ok($"Plano atualizado com sucesso");
            }
            catch (Exception ex)
            {
                return StatusCode(500, "Erro interno: " + ex.Message);
            }
        }
        [HttpDelete]
        [Route("Delete/{id}")]
        [SwaggerResponse(200, "Plano excluído com sucesso")]
        [SwaggerResponse(404, "Plano não encontrado")]
        [SwaggerResponse(500, "Erro interno")]
        public async Task<IActionResult> Delete(int id)
        {
            try
            {
                var plano = await _unitOfWork.TipoPlanoServices.ObterPorId(id);
                if (plano == null)
                {
                    return NotFound("Plano não encontrado");
                }

                await _unitOfWork.TipoPlanoServices.Deletar(id);
                await _unitOfWork.TipoPlanoServices.Salvar();

                return Ok("Plano excluído com sucesso");
            }
            catch (Exception ex)
            {
                return StatusCode(500, "Erro interno: " + ex.Message);
            }
        }
    }
}

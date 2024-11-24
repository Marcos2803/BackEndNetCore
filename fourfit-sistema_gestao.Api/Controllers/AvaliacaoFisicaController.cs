using fourfit.sistema_gestao.Domain.Entities.Alunos;
using fourfit.sistema_gestao.Domain.Interfaces;
using fourfit_sistema_gestao.Api.Models.Alunos;
using fourfit_sistema_gestao.Api.Models.AvaliacaoFisica;
using fourfit_sistema_gestao.Api.Validation;

using Microsoft.AspNetCore.Mvc;
using Swashbuckle.AspNetCore.Annotations;
using AvaliacaoFisica = fourfit.sistema_gestao.Domain.Entities.Alunos.AvaliacaoFisica;

namespace fourfit_sistema_gestao.Api.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AvaliacaoFisicaController : ControllerBase
    {
        private readonly IUnitOfWork _unitOfWork;

        public AvaliacaoFisicaController(IUnitOfWork unitOfWork)
        {
            _unitOfWork = unitOfWork;
        }
        [HttpPost]
        [Route("Register")]
        //[Authorize]
        [SwaggerResponse(statusCode: 200, description: "Avaliação física cadastrado com sucesso", Type = typeof(AvaliacaoFisicaViewModels))]
        [SwaggerResponse(statusCode: 400, description: "Campos obrigatórios", Type = typeof(ValidarCampos))]
        [SwaggerResponse(statusCode: 500, description: "Erro internet", Type = typeof(ErrosGenericos))]
        [SwaggerResponse(statusCode: 401, description: "Não autorizado", Type = typeof(ValidarCampos))]
        [SwaggerResponse(statusCode: 404, description: "Usuário nao autenticado", Type = typeof(AvaliacaoFisicaViewModels))]
        public async Task<IActionResult> Register(AvaliacaoFisicaViewModels model)
        {
            try
            {
                var avaliacaofisica = new AvaliacaoFisica
                {
                    Id = model.Id,
                    AlunosId = model.AlunosId,
                    DataAvaliacao = DateTime.Now,
                    Idade = model.Idade,
                    Altura = model.Altura,
                    Peso = model.Peso,
                    PercentualGordura = model.PercentualGordura,
                    MassaMagra = model.MassaMagra,
                    TaxaMetabolica = model.TaxaMetabolica,
                    GorduraVisceral = model.GorduraVisceral,
                    Imc = model.Imc,
                    IdadeCorporal = model.IdadeCorporal,
                    BicepsRelaxadoD = model.BicepsRelaxadoD,
                    BicepsRelaxadoE = model.BicepsRelaxadoE,
                    BicepsContraidoD = model.BicepsContraidoD,
                    BicepsContraidoE = model.BicepsContraidoE,
                    AntebracoD = model.AntebracoD,
                    AntebracoE = model.AntebracoE,
                    Costa = model.Costa,
                    Peitoral = model.Peitoral,
                    Cintura = model.Cintura,
                    Abdomen = model.Abdomen,
                    Quadril = model.Quadril,
                    CoxaD = model.CoxaD,
                    CoxaE = model.CoxaE,
                    PanturrilhaD = model.PanturrilhaD,
                    PanturrilhaE = model.PanturrilhaE

                };

                await _unitOfWork.AvaliacaoFisicaServices.Cadastro(avaliacaofisica);
                await _unitOfWork.AvaliacaoFisicaServices.Salvar();
                return Ok($"Avaliação física cadastrados com sucesso");
            }
            catch (Exception ex)
            {

                throw new Exception(ex.Message);
            }

        }

        [HttpGet]
        [Route("Update/{id}")]
        [SwaggerResponse(200, "Informações da avaliacão física obtidas com sucesso", typeof(AvaliacaoFisicaUpdateViewModels))]
        [SwaggerResponse(404, "Avaliação física não encontrado")]
        public async Task<IActionResult> Update(int id)
        {
            var model = await _unitOfWork.AvaliacaoFisicaServices.ObterAvaliacaoPorId(id);

            if (model == null)
            {
                return NotFound("Avaliação física não encontrado");
            }

            var avaliacaofisicaView = new AvaliacaoFisicaUpdateViewModels
            {
                Id = model.Id,
                AlunosId = model.AlunosId,
                DataAvaliacao = DateTime.Now,
                Idade = model.Idade,
                Altura = model.Altura,
                Peso = model.Peso,
                PercentualGordura = model.PercentualGordura,
                MassaMagra = model.MassaMagra,
                TaxaMetabolica = model.TaxaMetabolica,
                GorduraVisceral = model.GorduraVisceral,
                Imc = model.Imc,
                IdadeCorporal = model.IdadeCorporal,
                BicepsRelaxadoD = model.BicepsRelaxadoD,
                BicepsRelaxadoE = model.BicepsRelaxadoE,
                BicepsContraidoD = model.BicepsContraidoD,
                BicepsContraidoE = model.BicepsContraidoE,
                AntebracoD = model.AntebracoD,
                AntebracoE = model.AntebracoE,
                Costa = model.Costa,
                Peitoral = model.Peitoral,
                Cintura = model.Cintura,
                Abdomen = model.Abdomen,
                Quadril = model.Quadril,
                CoxaD = model.CoxaD,
                CoxaE = model.CoxaE,
                PanturrilhaD = model.PanturrilhaD,
                PanturrilhaE = model.PanturrilhaE
            };

            return Ok(avaliacaofisicaView);
        }

        [HttpPut]
        [Route("Update")]
        [SwaggerResponse(statusCode: 200, description: "Avaliação física atualizado com sucesso", Type = typeof(AvaliacaoFisicaUpdateViewModels))]
        [SwaggerResponse(statusCode: 400, description: "Campos obrigatórios", Type = typeof(ValidarCampos))]
        [SwaggerResponse(statusCode: 500, description: "Erro internet", Type = typeof(ErrosGenericos))]
        [SwaggerResponse(statusCode: 401, description: "Não autorizado", Type = typeof(ValidarCampos))]
        [SwaggerResponse(statusCode: 404, description: "Avaliação física não encontrado", Type = typeof(AvaliacaoFisicaUpdateViewModels))]
        public async Task<IActionResult> Update(AvaliacaoFisicaUpdateViewModels model)
        {
            try
            {

                var avaliacaofisica = await _unitOfWork.AvaliacaoFisicaServices.ObterPorId(model.Id);
                if (avaliacaofisica == null)
                {
                    return NotFound("Avaliação física não encontrado");
                }

                avaliacaofisica.AlunosId = model.AlunosId;
                avaliacaofisica.Id = model.Id;
                avaliacaofisica.Idade = model.Idade;
                avaliacaofisica.Altura = model.Altura;
                avaliacaofisica.Peso = model.Peso;
                avaliacaofisica.PercentualGordura = model.PercentualGordura;
                avaliacaofisica.MassaMagra = model.MassaMagra;
                avaliacaofisica.TaxaMetabolica = model.TaxaMetabolica;
                avaliacaofisica.GorduraVisceral = model.GorduraVisceral;
                avaliacaofisica.Imc = model.Imc;
                avaliacaofisica.IdadeCorporal = model.IdadeCorporal;
                avaliacaofisica.BicepsRelaxadoD = model.BicepsRelaxadoD;
                avaliacaofisica.BicepsRelaxadoE = model.BicepsRelaxadoE;
                avaliacaofisica.BicepsContraidoD = model.BicepsContraidoD;
                avaliacaofisica.BicepsContraidoE = model.BicepsContraidoE;
                avaliacaofisica.AntebracoD = model.AntebracoD;
                avaliacaofisica.AntebracoE = model.AntebracoE;
                avaliacaofisica.Costa = model.Costa;
                avaliacaofisica.Peitoral = model.Peitoral;
                avaliacaofisica.Abdomen = model.Abdomen;
                avaliacaofisica.Quadril = model.Quadril;
                avaliacaofisica.CoxaD = model.CoxaD;
                avaliacaofisica.CoxaE = model.CoxaE;
                avaliacaofisica.PanturrilhaD = model.PanturrilhaD;
                avaliacaofisica.PanturrilhaE = model.PanturrilhaE;

                await _unitOfWork.AvaliacaoFisicaServices.Atualizar(avaliacaofisica);
                await _unitOfWork.AvaliacaoFisicaServices.Salvar();

                return Ok($"Aluno atualizado com sucesso");
            }
            catch (Exception ex)
            {
                return StatusCode(500, "Erro interno: " + ex.Message);
            }
        }
        [HttpDelete]
        [Route("Delete/{id}")]
        [SwaggerResponse(200, "Avaliação física excluído com sucesso")]
        [SwaggerResponse(404, "Avaliação física não encontrado")]
        [SwaggerResponse(500, "Erro interno")]
        public async Task<IActionResult> Delete(int id)
        {
            try
            {
                var avaliacaofisica = await _unitOfWork.AvaliacaoFisicaServices.ObterPorId(id);
                if (avaliacaofisica == null)
                {
                    return NotFound("Avaliação física não encontrado");
                }

                await _unitOfWork.AvaliacaoFisicaServices.Deletar(id);
                await _unitOfWork.AvaliacaoFisicaServices.Salvar();

                return Ok("Avaliação física excluído com sucesso");
            }
            catch (Exception ex)
            {
                return StatusCode(500, "Erro interno: " + ex.Message);
            }
        }
    }
}

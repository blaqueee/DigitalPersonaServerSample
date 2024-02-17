package com.axelor.sale.web;

import com.axelor.auth.db.FingerprintFormat;
import com.axelor.auth.db.User;
import com.axelor.auth.db.repo.UserRepository;
import com.axelor.rpc.Response;
import com.axelor.sale.dto.FingerprintCompareDto;
import com.digitalpersona.uareu.Engine;
import com.digitalpersona.uareu.Fmd;
import com.digitalpersona.uareu.UareUException;
import com.digitalpersona.uareu.UareUGlobal;
import com.digitalpersona.uareu.jni.Dpfj;
import com.google.inject.Inject;

import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import java.util.Map;
import java.util.Objects;

@Path("/public/fingerprint")
@Consumes(MediaType.APPLICATION_JSON)
@Produces(MediaType.APPLICATION_JSON)
public class UserPublicService {
    private final UserRepository userRepository;
    private final Engine engine = UareUGlobal.GetEngine();
    private final Dpfj dpfj = new Dpfj();
    private final int FALSE_POSITIVE_RATE = Engine.PROBABILITY_ONE / 100000;

    @Inject
    public UserPublicService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Path("/compare")
    @POST
    public Response compare(FingerprintCompareDto dto) throws UareUException {
        Response response = new Response();

        User user = userRepository.findByCode(dto.getCode());
        if (user == null) {
            response.setErrors(Map.of("message", "User not found"));
            response.setStatus(Response.STATUS_LOGIN_INCORRECT);
            return response;
        }

        byte[] fingerprintData = user.getFingerprintData();
        Fmd.Format fingerprintFormat = null;

        FingerprintFormat format = user.getFingerprintFormat();
        if (format.getValue().equals("ANSI_378_2004"))
            fingerprintFormat = Fmd.Format.ANSI_378_2004;

        byte[] fingerprintDataDto = dto.getFingerprint().getData();
        Fmd.Format fingerprintFormatDto = null;
        if (Objects.equals("ANSI_378_2004", dto.getFingerprint().getFormat()))
            fingerprintFormatDto = Fmd.Format.ANSI_378_2004;

        Fmd storedFmd = dpfj.import_fmd(fingerprintData, fingerprintFormat, fingerprintFormat);
        Fmd requestedFmd = dpfj.import_fmd(fingerprintDataDto, fingerprintFormatDto, fingerprintFormatDto);

        int compare = engine.Compare(storedFmd, 0, requestedFmd, 0);

        if (compare < FALSE_POSITIVE_RATE) {
            response.setStatus(Response.STATUS_SUCCESS);
            response.setData(true);
            return response;
        }
        response.setStatus(Response.STATUS_LOGIN_INCORRECT);
        response.setData(false);
        return response;
    }

}

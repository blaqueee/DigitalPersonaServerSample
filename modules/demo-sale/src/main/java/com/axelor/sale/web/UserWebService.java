package com.axelor.sale.web;

import com.axelor.auth.AuthUtils;
import com.axelor.auth.db.FingerprintFormat;
import com.axelor.auth.db.User;
import com.axelor.auth.db.repo.UserRepository;
import com.axelor.rpc.Response;
import com.axelor.sale.dto.FingerprintDto;
import com.google.inject.Inject;
import com.google.inject.persist.Transactional;

import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import java.util.Objects;

@Path("/user")
@Consumes(MediaType.APPLICATION_JSON)
@Produces(MediaType.APPLICATION_JSON)
public class UserWebService {
    private final UserRepository userRepository;

    @Inject
    public UserWebService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Path("/enroll")
    @POST
    @Transactional(rollbackOn = {Exception.class})
    public Response enroll(FingerprintDto fingerprint) {
        User user = AuthUtils.getUser();
        user.setFingerprintData(fingerprint.getData());
        if (Objects.equals("ANSI_378_2004", fingerprint.getFormat()))
            user.setFingerprintFormat(FingerprintFormat.ANSI_378_2004);
        User saved = userRepository.save(user);
        Response response = new Response();
        response.setData(saved);
        return response;
    }

}
